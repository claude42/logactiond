/*
 *  logactiond - trigger actions based on logfile contents
 *  Copyright (C) 2019-2021 Klaus Wissmann

 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.

 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#ifndef NOMONITORING

#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <stdnoreturn.h>

#include "ndebug.h"
#include "logactiond.h"
#include "addresses.h"
#include "commands.h"
#include "configfile.h"
#include "endqueue.h"
#include "logging.h"
#include "misc.h"
#include "rules.h"
#include "sources.h"
#include "status.h"
#include "metacommands.h"

int status_monitoring = 0;

pthread_t monitoring_thread = 0;

static FILE *
open_diag_file(const char *mode)
{
        FILE *result = NULL;

        if (status_monitoring >= 2)
        {
                result = fopen(DIAGFILE, mode);
                if (!result)
                        die_hard(true, "Can't create \"" DIAGFILE "\"");
        }

        return result;
}

static void
dump_queue_pointers(void)
{
        la_vdebug_func(NULL);
        if (status_monitoring < 2 || !queue_pointers)
                return;

        FILE *const diag_file = open_diag_file("a");

        xpthread_mutex_lock(&end_queue_mutex);

                fprintf(diag_file, "\nqueue pointer list (length=%i)\n",
                                list_length(queue_pointers));

                FOREACH(la_queue_pointer_t, qp, queue_pointers)
                        fprintf(diag_file, "%i[%li] -> %s (%li)\n",
                                        qp->duration, qp->node.pri,
                                        (qp->command && qp->command->address) ?
                                        qp->command->address->text : NULL,
                                        qp->command ? qp->command->end_time : -1);

        xpthread_mutex_unlock(&end_queue_mutex);

        if (fclose(diag_file))
                die_hard(true, "Can't close \" DIAGFILE \"");
}

/*
 * Convert time_t into human readable format. Return values are in *value and
 * *unit...
 */

static void
human_readable_time_delta(const time_t delta, time_t *const value,
                char *const unit)
{
        assert(value); assert(unit);
        
        if (delta <= 0)
        {
                *value = 0;
                *unit = 's';
                return;
        }
        *value = delta;
        if (*value < 60)
        {
                *unit = 's';
                return;
        }

        *value = *value / 60;
        if (*value < 60)
        {
                *unit = 'm';
                return;
        }

        *value = *value / 60;
        if (*value < 24)
        {
                *unit = 'h';
                return;
        }

        *value = *value / 24;
        *unit = 'd';
}

static void
dump_rule_diagnostics(FILE *const diag_file, const la_rule_t *const rule)
{
        assert(diag_file), assert_rule(rule);
        la_vdebug_func(rule->node.nodename);

        fprintf(diag_file, "%s, list length=%i\n", rule->node.nodename,
                        list_length(&rule->trigger_list));
}

/*
 * Write single line to the rule status file.
 */

static void
dump_single_rule(FILE *const rules_file, const la_rule_t *const rule)
{
        assert(rules_file), assert_rule(rule);
        la_vdebug_func(rule->node.nodename);
        fprintf(rules_file, RULES_LINE,
                        rule->enabled ? 'Y' : 'N', rule->node.nodename,
                        rule->systemd_unit ? rule->systemd_unit : rule->service ? rule->service : "-",
                        rule->source_group->node.nodename, rule->detection_count,
                        rule->invocation_count, rule->queue_count);
}

/*
 * Write rule status file to disc
 */

void
dump_rules(void)
{
        la_debug_func(NULL);

        FILE *const rules_file = fopen(RULESFILE, "w");
        if (!rules_file)
                die_hard(true, "Can't create \"" RULESFILE "\"");

        FILE *const diag_file = open_diag_file("w");

        fputs(RULES_HEADER, rules_file);

        xpthread_mutex_lock(&config_mutex);

                /* First print rules of sources watched via inotify / polling */

                assert(la_config); assert_list(&la_config->source_groups);
                FOREACH(la_source_group_t, source_group, &la_config->source_groups)
                {
                        FOREACH(la_rule_t, rule, &source_group->rules)
                        {
                                dump_single_rule(rules_file, rule);
                                if (status_monitoring >= 2)
                                        dump_rule_diagnostics(diag_file, rule);
                        }
                }

#if HAVE_LIBSYSTEMD
                /* Then print systemd rules - if any */
                if (la_config->systemd_source_group)
                {
                        FOREACH(la_rule_t, rule, &la_config->systemd_source_group->rules)
                        {
                                dump_single_rule(rules_file, rule);
                                if (status_monitoring >= 2)
                                        dump_rule_diagnostics(diag_file, rule);
                        }
                }
#endif /* HAVE_LIBSYSTEMD */

        xpthread_mutex_unlock(&config_mutex);

        if (fclose(rules_file))
                die_hard(true, "Can't close \" RULESTSFILE \"");
        if (status_monitoring >= 2 && fclose(diag_file))
                die_hard(true, "Can't close \" DIAGFILE \"");
}

/*
 * Remove all previously created status files
 */

static void
cleanup_monitoring(void *const arg)
{
        la_debug_func(NULL);

        if (remove(HOSTSFILE) && errno != ENOENT)
                la_log_errno(LOG_ERR, "Can't remove host status file");
        if (remove(RULESFILE) && errno != ENOENT)
                la_log_errno(LOG_ERR, "Can't remove rule status file");
        if (status_monitoring >= 2 && remove(DIAGFILE) && errno != ENOENT)
                la_log_errno(LOG_ERR, "Can't remove diagnostics file");

        monitoring_thread = 0;
        /* Big TODO: this will currently break when status monitoring will be
         * disabled via ladc. */
        wait_final_barrier();
        la_debug("status thread exiting");
}

/*
 * Regularly dump logfiles
 */

noreturn static void *
dump_loop(void *const ptr)
{
        la_debug_func(NULL);

        pthread_cleanup_push(cleanup_monitoring, NULL);

        sleep(1);

        for (;;)
        {
                if (shutdown_ongoing || !status_monitoring)
                {
                        la_debug("Shutting down monitoring thread.");
                        pthread_exit(NULL);
                }

                dump_rules();

                dump_queue_status(false);

                dump_queue_pointers();

                sleep(5);
        }

        assert(false);
        /* Will never be reached, simply here to make potential pthread macros
         * happy */
        pthread_cleanup_pop(1);
}

/*
 * Start monitoring thread
 */

void
start_monitoring_thread(void)
{
        la_debug_func(NULL);
        if (!status_monitoring)
                return;
        if (monitoring_thread)
                return;

        xpthread_create(&monitoring_thread, NULL, dump_loop, NULL, "status");
        thread_started(monitoring_thread);
        la_debug("status thread started (%i)", monitoring_thread);
}

static const char *
get_type_string(const la_command_t *const command)
{
        if (command->submission_type == LA_SUBMISSION_MANUAL)
                return "Ma";
        else if (command->submission_type == LA_SUBMISSION_REMOTE)
                return "Re";
        else if (command->submission_type == LA_SUBMISSION_RENEW)
                return "RN";
        else if (command->previously_on_blacklist)
                return "BL";
        else
                return "  ";
}

/*
 * Dumps a summary of a list of commands (usually the end queue) to a file.
 *
 * NOTE: must be called with end_queue_mutex locked when called for the end
 * queue.
 *
 * Runs in end_queue_thread
 */

/* TODO: as this accesses meta_list_length() this might necessitate locking the
 * config_mutex. It is called from endqueue_end_command() (which has the mutex
 * locked already) as well as empty_end_queue() and consume_end_queue() which
 * don't have that lock. Should have a good look at it!
 */

void
dump_queue_status(const bool force)
{
        la_vdebug_func(NULL);

        if ((!status_monitoring && !force) || shutdown_ongoing)
                return;

        FILE *const hosts_file = fopen(HOSTSFILE, "w");
        if (!hosts_file)
                die_hard(false, "Can't create \"" HOSTSFILE "\"!");

        FILE *const diag_file = open_diag_file("a");

        const time_t now = xtime(NULL);
        char date_string[26];
        fprintf(hosts_file, HOSTS_HEADER, ctime_r(&now, date_string));

        int num_elems = 0;
        int num_elems_local = 0;
        int max_depth = 0;
        int num_items = 0;

        xpthread_mutex_lock(&end_queue_mutex);

                for (la_command_t *command = first_command_in_queue(); command;
                                (command = next_command_in_queue(command)))
                {
                        /* Don't assert_command() here, as after a reload some
                         * commands might not have a rule attached to them
                         * anymore */
                        assert(command); assert(command->node.nodename);
                        /* not interested in shutdown commands (or anything
                         * beyond...) */
                        if (command->end_time == INT_MAX)
                                break;

                        /* First  collect data for the queue length line */
                        if ((status_monitoring >= 2 || force) &&
                                        !command->is_template)
                        {
                                num_elems++;
                                if (command->submission_type ==
                                                LA_SUBMISSION_LOCAL)
                                        num_elems_local++;
                        }

                        /* Second build host table */
                        const char *const adr = command->address ?
                                command->address->text : "-";
                        const int depth = node_depth(&command->adr_node);
                        if (depth > max_depth)
                                max_depth = depth;
                        num_items++;

                        time_t timedelta;
                        char unit;
                        human_readable_time_delta(command->end_time-xtime(NULL),
                                        &timedelta, &unit);

                        const char *const type = get_type_string(command);

                        if (status_monitoring >= 2)
                                fprintf(hosts_file, HOSTS_LINE_V, adr, type,
                                                command->factor, timedelta,
                                                unit, command->rule_name,
                                                command->node.nodename, depth, num_items);
                        else
                                fprintf(hosts_file, HOSTS_LINE, adr, type,
                                                command->factor, timedelta,
                                                unit, command->rule_name,
                                                command->node.nodename);
                }

                if (status_monitoring >= 2 || force)
                {
                        fputs("\n", diag_file);
                        fprintf(diag_file, "\nQueue length: %i (%i local), "
                                        "meta_command: %i\n",
                                        num_elems, num_elems_local,
                                        meta_list_length());

                        fprintf(diag_file, "adr_tree depth=%i, end_time_list length=%i\n",
                                        max_depth, num_items);

                        const float average_time = la_config->invocation_count ?
                                (float) la_config->total_clocks /
                                (float) la_config->invocation_count: 0;
                        fprintf(diag_file, "Average invocation time: %f, "
                                        "(invocation count: %i)\n",
                                        average_time,
                                        la_config->invocation_count);

                        const float average_cmps = la_config->total_et_invs ?
                                (float) la_config->total_et_cmps /
                                (float) la_config->total_et_invs : 0;
                        fprintf(diag_file, "Average end_time_list comparissons: %f, "
                                        "(invocation count: %i)\n",
                                        average_cmps,
                                        la_config->total_et_invs);
                }

        xpthread_mutex_unlock(&end_queue_mutex);

        if (fclose(hosts_file))
                die_hard(false, "Can't close \" HOSTSFILE \"!");
        if (status_monitoring >= 2 && fclose(diag_file))
                die_hard(true, "Can't close \" DIAGFILE \"");
}

#endif /* NOMONITORING */

/* vim: set autowrite expandtab: */
