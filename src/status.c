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

static pthread_mutex_t monitoring_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t monitoring_condition = PTHREAD_COND_INITIALIZER;

/*static void *
dump_single_pattern(FILE *rules_file, la_pattern_t *pattern)
{
        assert(rules_file), assesrt_pattern(pattern);
}

static void *
dump_single_rule(FILE *rules_file, la_rule_t *rule)
{
        assert(rules_file), assert_rule(rule);
        fprintf(rules_file, "%s\n", rule->name);
        for (int i=strlen(rule->name); i>0; i--)
                fputc('=', rules_file);
        fputc('\n', rules_file);

        for (la_pattern_t *pattern = ITERATE_PATTERNS(rule->patterns);
                        (pattern = NEXT_PATTERN(pattern));)
                dump_single_pattern(rules_file, pattern);
}*/

/*
 * Write single line to the rule status file.
 */

static void *
dump_single_rule(FILE *rules_file, la_rule_t *rule)
{
        assert(rules_file), assert_rule(rule);
        la_vdebug("dump_single_rule(%s)", rule->name);
        la_vdebug("%-13.13s %-9.9s %-9.9s %9u %9u\n",
                        rule->name, rule->service, rule->source->name,
                        rule->detection_count, rule->invocation_count);
        fprintf(rules_file, "%-13.13s %-13.13s %-13.13s %8u %8u\n",
                        rule->name, rule->service, rule->source->name,
                        rule->detection_count, rule->invocation_count);
}

/*
 * Write rule status file to disc
 */

static void *
dump_rules(void)
{
        la_debug("dump_rules()");

        FILE *rules_file = fopen(RULESFILE, "w");
        if (!rules_file)
                die_err("Can't create \"" RULESFILE "\"!");
        fprintf(rules_file, "Rule          Service       Source        Detected  Invoked  \n");
        fprintf(rules_file, "===========================================================\n");

        pthread_mutex_lock(&config_mutex);

        for (la_source_t *source = ITERATE_SOURCES(la_config->sources);
                        (source = NEXT_SOURCE(source));)
        {
                for (la_rule_t *rule = ITERATE_RULES(source->rules);
                                (rule = NEXT_RULE(rule));)
                        dump_single_rule(rules_file, rule);
        }

        pthread_mutex_unlock(&config_mutex);

        if (fclose(rules_file))
                die_hard("Can't close \" HOSTSFILE \"!");
}

/*
 * Regularly dump logfiles
 */

static void *
dump_loop(void *ptr)
{
        la_debug("dump_loop()");

        xpthread_mutex_lock(&monitoring_mutex);

        struct timespec wait_interval;

        for (;;)
        {
                la_vdebug("dump_loop() looping");
                wait_interval.tv_nsec = 0;
                wait_interval.tv_sec = xtime(NULL) + 5;
                xpthread_cond_timedwait(&monitoring_condition, &monitoring_mutex,
                                &wait_interval);
                if (shutdown_ongoing)
                {
                        la_debug("Shutting down monitoring thread.");
                        xpthread_mutex_unlock(&monitoring_mutex);
                        pthread_exit(NULL);
                }

                dump_rules();
        }
}

/*
 * Start monitoring thread
 */

void
init_monitoring(void)
{
        la_debug("init_monitoring()");
        if (!status_monitoring)
                return;

        pthread_t monitoring_thread;

        xpthread_create(&monitoring_thread, NULL, dump_loop, NULL);
}

void
shutdown_monitoring(void)
{
        la_debug("shutdown_monitoring()");
        xpthread_cond_signal(&monitoring_condition);
}

/*
 * Remove all previously created status files
 */

void
remove_status_files(void)
{
        if (!status_monitoring)
                return;

        if (remove(HOSTSFILE) && errno != ENOENT)
                die_err("Can't remove host status file!");
        if (remove(RULESFILE) && errno != ENOENT)
                die_err("Can't remove rule status file!");
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

        fprintf(hosts_file, "IP address                                     "
                        "Time     Rule      Action\n"
                        "======================================"
                        "=========================================\n");

        /* INET6_ADDRSTRLEN 46 + "/123*/

        for (la_command_t *command = ITERATE_COMMANDS(queue);
                        (command = NEXT_COMMAND(command));)
        {
                assert_command(command);
                // not interested in shutdown commands (or anything beyond...)
                if (command->end_time == INT_MAX)
                        break;
                la_debug("printing %s", command->name);

                char *adr = command->address ? command->address->text : "-";

                char end_time[10];
                strftime(end_time, 9, "%T", localtime(&(command->end_time)));

                fprintf(hosts_file,
                                "%-46.46s %-8.8s %-9.9s %-13.13s\n",
                                adr, end_time, command->rule->name,
                                command->name);
        }

        if (fclose(hosts_file))
                die_hard("Can't close \" HOSTSFILE \"!");
}

/* vim: set autowrite expandtab: */
