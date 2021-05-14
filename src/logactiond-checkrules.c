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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <getopt.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <regex.h>
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
#endif /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */

#include "ndebug.h"
#include "commands.h"
#include "configfile.h"
#include "logactiond.h"
#include "logging.h"
#include "misc.h"
#include "patterns.h"
#include "rules.h"
#include "sources.h"
#include "logging.h"
#include "nodelist.h"
#include "binarytree.h"

la_runtype_t run_type = LA_UTIL_FOREGROUND;

static char *cfg_filename = NULL;
static char *log_filename = NULL;
static char *rule_name = NULL;
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
        atomic_bool shutdown_ongoing = ATOMIC_VAR_INIT(false);
#else /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */
        bool shutdown_ongoing = false;
#endif /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */
int exit_status = EXIT_SUCCESS;
bool show_undetected = false;
const char *const pidfile_name = PIDFILE;

void
trigger_shutdown(int status, int saved_errno)
{
        exit_status = status;
        shutdown_ongoing = true;
}

static void
print_usage(void)
{
        fprintf(stderr,
        "Usage: logactiond-checkrule [-u] [-c configfile] [-d] [-r rule] [-v] [file]\n");
}

static void
read_options(int argc, char *argv[])
{
        la_debug_func(NULL);

        for (;;)
        {
                static struct option long_options[] =
                {
                        {"undetected", no_argument,       NULL, 'u'},
                        {"rule",       required_argument, NULL, 'r'},
                        {"configfile", required_argument, NULL, 'c'},
                        {"debug",      optional_argument, NULL, 'd'},
                        {"verbose",    no_argument,       NULL, 'v'},
                        {0,            0,                 0,    0  }
                };

                int c = getopt_long(argc, argv, "ur:c:d::v", long_options, NULL);

                if (c == -1)
                        break;
                
                switch (c)
                {
                        case 'u':
                                show_undetected = true;
                                break;
                        case 'r': 
                                rule_name = optarg;
                                break;
                        case 'c':
                                cfg_filename = optarg;
                                break;
                        case 'd': 
                                log_level++;
                                if (optarg && *optarg == 'd')
                                        log_level++;
                                break;
                        case 'v': 
                                break;
                        case '?':
                                print_usage();
                                exit(0);
                                break;
                        default:
                                printf("Getop returnd character code %c\n", c);
                                break;

                }
        }
        if (optind < argc)
                log_filename = argv[optind];
}

static void
next_line(la_rule_t *rule, char *line)
{
        assert_rule(rule); assert(line);

        la_debug_func(line);

        FOREACH(la_pattern_t, pattern, &rule->patterns)
        {
                la_debug("pattern %u: %s\n", pattern->num, pattern->string);
                /* TODO: make this dynamic based on detected tokens */
                regmatch_t pmatch[MAX_NMATCH];
                if (!regexec(&(pattern->regex), line, MAX_NMATCH, pmatch, 0))
                {
                        if (!show_undetected)
                        {
                                printf("%s(%i): %s", rule->node.nodename, pattern->num, line);
                                if (line[strlen(line)-1] != '\n')
                                        printf("\n");
                        }
                        else
                        {
                                return;
                        }
                }
        }

        if (show_undetected)
        {
                printf("%s", line);
                if (line[strlen(line)-1] != '\n')
                        printf("\n");
        }
}

static void
iterate_through_all_rules(char *line)
{
        la_debug_func(NULL);

        FOREACH(la_source_group_t, source_group, &la_config->source_groups)
        {
                FOREACH(la_rule_t, rule, &source_group->rules)
                        next_line(rule, line);
        }

#if HAVE_LIBSYSTEMD
        if (la_config->systemd_source_group)
        {
                FOREACH(la_rule_t, rule, &la_config->systemd_source_group->rules)
                        next_line(rule, line);
        }
#endif /* HAVE_LIBSYSTEMD */
}

int
main(int argc, char *argv[])
{
        FILE *file;

        inject_misc_exit_function(die_hard);
        inject_nodelist_exit_function(die_hard);
        inject_binarytree_exit_function(die_hard);

        read_options(argc, argv);

        if (chdir(CONF_DIR) == -1)
                die_hard(true, "Can't change to configuration directory");

        if (!init_la_config(cfg_filename))
                die_hard(false, "Error loading configuration.");
        load_la_config();

        if (log_filename)
        {
                file = fopen(log_filename, "r");
                if (!file)
                        die_hard(true, "Opening file \"%s\" failed", log_filename);
        }
        else
        {
                file = stdin;
        }

        la_rule_t *one_rule = NULL;
        if (rule_name)
        {
                one_rule = find_rule(rule_name);
                if (!one_rule)
                        die_hard(false, "Can't find rule %s.", rule_name);
        }
        
        size_t linebuffer_size = 0;
        char *linebuffer = NULL;

        for (;;)
        {
		const ssize_t num_read = getline(&linebuffer, &linebuffer_size, file);
		if (num_read==-1)
		{
			if (feof(file))
				break;
			else
                                die_hard(true, "Reading from file \"%s\" failed",
                                                log_filename);
		}
                if (one_rule)
                        next_line(one_rule, linebuffer);
                else
                        iterate_through_all_rules(linebuffer);
        }

        free(linebuffer);

        /* This whole exit procedure doesn't make much sense for a standalone
         * tool. We're just obeying to the infrastructure set in place by the
         * main daemon. */
        trigger_shutdown(EXIT_SUCCESS, 0);

        unload_la_config();
        exit(exit_status);
}


/* vim: set autowrite expandtab: */

