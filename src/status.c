/*
 *  logactiond - trigger actions based on logfile contents
 *  Copyright (C) 2019  Klaus Wissmann

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

#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>

//#include <libconfig.h>

#include "logactiond.h"
#include "nodelist.h"

pthread_t monitoring_thread = 0;

/*
 * Convert time_t into human readable format. Return values are in *value and
 * *unit...
 */

static void
human_readable_time_delta(time_t delta, int *value, char *unit)
{
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
dump_rule_diagnostics(FILE *diag_file, la_rule_t *rule)
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
dump_single_rule(FILE *rules_file, la_rule_t *rule)
{
        assert(rules_file), assert_rule(rule);
        la_vdebug("dump_single_rule(%s)", rule->name);
        fprintf(rules_file, "%-13.13s %-13.13s %-13.13s %8lu %8lu %8lu\n",
                        rule->name, rule->systemd_unit ? rule->systemd_unit :
                        rule->service, rule->source->name,
                        rule->detection_count, rule->invocation_count,
                        rule->queue_count);
}

/*
 * Write rule status file to disc
 */

static void
dump_rules(void)
{
        la_debug("dump_rules()");

        FILE *rules_file = fopen(RULESFILE, "w");
        if (!rules_file)
                die_err("Can't create \"" RULESFILE "\"!");

        FILE *diag_file = NULL;
        if (status_monitoring >= 2)
        {
                diag_file = fopen(DIAGFILE, "w");
                if (!diag_file)
                        die_err("Can't create \"" DIAGFILE "\"!");
        }

        fprintf(rules_file, "Rule          Service       Source        Detected  Invoked  In queue\n");
        fprintf(rules_file, "=====================================================================\n");

        xpthread_mutex_lock(&config_mutex);

        /* First print rules of sources watched via inotify / polling */

        for (la_source_t *source = ITERATE_SOURCES(la_config->sources);
                        (source = NEXT_SOURCE(source));)
        {
                for (la_rule_t *rule = ITERATE_RULES(source->rules);
                                (rule = NEXT_RULE(rule));)
                {
                        dump_single_rule(rules_file, rule);
                        if (status_monitoring >= 2)
                                dump_rule_diagnostics(diag_file, rule);
                }
        }

#if HAVE_LIBSYSTEMD
        /* Then print systemd rules - if any */
        if (la_config->systemd_source)
        {
                for (la_rule_t *rule = ITERATE_RULES(la_config->systemd_source->rules);
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
                die_hard("Can't close \" RULESTSFILE \"!");
        if (status_monitoring >= 2)
                if (fclose(diag_file))
                        die_hard("Can't close \" DIAGFILE \"!");
}

/*
 * Remove all previously created status files
 */

void
remove_status_files(void *arg)
{
        la_debug("remove_status_files()");
        if (!status_monitoring)
                return;

        if (remove(HOSTSFILE) && errno != ENOENT)
                die_err("Can't remove host status file!");
        if (remove(RULESFILE) && errno != ENOENT)
                die_err("Can't remove rule status file!");
        if (status_monitoring >=2)
                if (remove(DIAGFILE) && errno != ENOENT)
                        die_err("Can't remove diagnostics file!");
}

/*
 * Regularly dump logfiles
 */

static void *
dump_loop(void *ptr)
{
        la_debug("dump_loop()");

        pthread_cleanup_push(remove_status_files, NULL);

        struct timespec wait_interval;

        for (;;)
        {
                sleep(5);
                if (shutdown_ongoing)
                {
                        la_debug("Shutting down monitoring thread.");
                        pthread_exit(NULL);
                }

                dump_rules();

                xpthread_mutex_lock(&end_queue_mutex);
                dump_queue_status(end_queue);
                xpthread_mutex_unlock(&end_queue_mutex);
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

void
dump_queue_status(kw_list_t *queue)
{
        la_vdebug("dump_queue_status()");
        if (!status_monitoring || shutdown_ongoing)
                return;

        FILE *hosts_file = fopen(HOSTSFILE, "w");
        if (!hosts_file)
                die_err("Can't create \"" HOSTSFILE "\"!");

        if (status_monitoring >= 2)
        {
                fprintf(hosts_file, "Queue length: %u\n\n",
                                list_length(queue));
        }

        fprintf(hosts_file, "IP address                                     "
                        "Time Rule          Action\n"
                        "======================================"
                        "=========================================\n");

        /* INET6_ADDRSTRLEN 46 + "/123" */

        for (la_command_t *command = ITERATE_COMMANDS(queue);
                        (command = NEXT_COMMAND(command));)
        {
                /* Don't assert_command() here, as after a reload some commands might
                 * not have a rule attached to them anymore */
                assert(command); assert(command->name);
                assert_address(command->address);
                // not interested in shutdown commands (or anything beyond...)
                if (command->end_time == INT_MAX)
                        break;

                char *adr = command->address ? command->address->text : "-";

                int timedelta;
                char unit;
                human_readable_time_delta(command->end_time-xtime(NULL),
                                &timedelta, &unit);

                fprintf(hosts_file,
                                "%-46.46s %2u%c  %-13.13s %-13.13s\n",
                                adr, timedelta, unit, command->rule_name,
                                command->name);
        }

        if (fclose(hosts_file))
                die_hard("Can't close \" HOSTSFILE \"!");
}

/* vim: set autowrite expandtab: */
