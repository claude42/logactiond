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
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>

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

int status_monitoring = 0;

pthread_t monitoring_thread = 0;

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
        la_vdebug("dump_rule_diagnostics(%s)", rule->name);

        fprintf(diag_file, "%s, list length=%u\n", rule->name,
                        list_length(rule->trigger_list));
}

/*
 * Write single line to the rule status file.
 */

static void
dump_single_rule(FILE *const rules_file, const la_rule_t *const rule)
{
        assert(rules_file), assert_rule(rule);
        la_vdebug("dump_single_rule(%s)", rule->name);
        fprintf(rules_file, RULES_LINE,
                        rule->enabled ? 'Y' : 'N', rule->name,
                        rule->systemd_unit ? rule->systemd_unit : rule->service ? rule->service : "-",
                        rule->source_group->name, rule->detection_count,
                        rule->invocation_count, rule->queue_count);
}

/*
 * Write rule status file to disc
 */

void
dump_rules(void)
{
        la_debug("dump_rules()");

        FILE *const rules_file = fopen(RULESFILE, "w");
        if (!rules_file)
                die_hard(true, "Can't create \"" RULESFILE "\"");

        FILE *diag_file = NULL;
        if (status_monitoring >= 2)
        {
                diag_file = fopen(DIAGFILE, "w");
                if (!diag_file)
                        die_hard(true, "Can't create \"" DIAGFILE "\"");
        }

        fputs(RULES_HEADER, rules_file);

        xpthread_mutex_lock(&config_mutex);

                /* First print rules of sources watched via inotify / polling */

                assert(la_config); assert(la_config->source_groups);
                for (la_source_group_t *source_group = ITERATE_SOURCE_GROUPS(la_config->source_groups);
                                (source_group = NEXT_SOURCE_GROUP(source_group));)
                {
                        for (la_rule_t *rule = ITERATE_RULES(source_group->rules);
                                        (rule = NEXT_RULE(rule));)
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
                        for (la_rule_t *rule = ITERATE_RULES(la_config->systemd_source_group->rules);
                                        (rule = NEXT_RULE(rule));)
                        {
                                dump_single_rule(rules_file, rule);
                                if (status_monitoring >= 2)
                                        dump_rule_diagnostics(diag_file, rule);
                        }
                }
#endif /* HAVE_LIBSYSTEMD */

        xpthread_mutex_unlock(&config_mutex);

        if (fclose(rules_file))
                die_hard(false, "Can't close \" RULESTSFILE \"");
        if (status_monitoring >= 2)
                if (fclose(diag_file))
                        die_hard(false, "Can't close \" DIAGFILE \"");
}

/*
 * Remove all previously created status files
 */

static void
cleanup_monitoring(void *const arg)
{
        la_debug("cleanup_monitoring()");

        monitoring_thread = 0;

        if (remove(HOSTSFILE) && errno != ENOENT)
                la_log_errno(LOG_ERR, "Can't remove host status file");
        if (remove(RULESFILE) && errno != ENOENT)
                la_log_errno(LOG_ERR, "Can't remove rule status file");
        if (status_monitoring >=2)
                if (remove(DIAGFILE) && errno != ENOENT)
                        la_log_errno(LOG_ERR, "Can't remove diagnostics file");
}

/*
 * Regularly dump logfiles
 */

static void *
dump_loop(void *const ptr)
{
        la_debug("dump_loop()");

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
        la_debug("init_monitoring()");
        if (!status_monitoring)
                return;
        assert(!monitoring_thread);

        xpthread_create(&monitoring_thread, NULL, dump_loop, NULL, "status");
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
        la_vdebug("dump_queue_status()");

        if ((!status_monitoring && !force) || shutdown_ongoing)
                return;

        FILE *const hosts_file = fopen(HOSTSFILE, "w");
        if (!hosts_file)
                die_hard(false, "Can't create \"" HOSTSFILE "\"!");

        const time_t now = xtime(NULL);
        char date_string[26];
        fprintf(hosts_file, HOSTS_HEADER, ctime_r(&now, date_string));

        int num_elems = 0;
        int num_elems_local = 0;
        int max_depth1 = 0;
        int max_depth2 = 0;

        xpthread_mutex_lock(&end_queue_mutex);

                for (la_command_t *command = first_command_in_queue(); command;
                                (command = next_command_in_queue(command)))
                {
                        /* Don't assert_command() here, as after a reload some
                         * commands might not have a rule attached to them
                         * anymore */
                        assert(command); assert(command->name);
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
                        const int depth1 = node_depth(&command->adr_node);
                        if (depth1 > max_depth1)
                                max_depth1 = depth1;
                        const int depth2 = node_depth(&command->end_time_node);
                        if (depth2 > max_depth2)
                                max_depth2 = depth2;

                        time_t timedelta;
                        char unit;
                        human_readable_time_delta(command->end_time-xtime(NULL),
                                        &timedelta, &unit);

                        const char *type;
                        if (command->submission_type == LA_SUBMISSION_MANUAL)
                                type = "Ma";
                        else if (command->submission_type == LA_SUBMISSION_REMOTE)
                                type = "Re";
                        else if (command->submission_type == LA_SUBMISSION_RENEW)
                                type = "RN";
                        else if (command->blacklist)
                                type = "BL";
                        else
                                type = "  ";

                        if (status_monitoring >= 2)
                                fprintf(hosts_file, HOSTS_LINE_V, adr, type,
                                                command->factor, timedelta,
                                                unit, command->rule_name,
                                                command->name, depth1, depth2);
                        else
                                fprintf(hosts_file, HOSTS_LINE, adr, type,
                                                command->factor, timedelta,
                                                unit, command->rule_name,
                                                command->name);
                }

                if (status_monitoring >= 2 || force)
                {
                        fprintf(hosts_file, "\nQueue length: %u (%u local), "
                                        "meta_command: %u\n",
                                        num_elems, num_elems_local,
                                        meta_list_length());

                        const float average_time = la_config->invocation_count ?
                                la_config->total_clocks / la_config->invocation_count :
                                0;
                        fprintf(hosts_file, "Average invocation time: %f, "
                                        "(invocation count: %u)\n",
                                        average_time,
                                        la_config->invocation_count);
                        fprintf(hosts_file, "adr_tree depth=%u, end_time_tree depth=%u\n",
                                        max_depth1, max_depth2);
                }

        xpthread_mutex_unlock(&end_queue_mutex);

        if (fclose(hosts_file))
                die_hard(false, "Can't close \" HOSTSFILE \"!");
}

#endif /* NOMONITORING */

/* vim: set autowrite expandtab: */
