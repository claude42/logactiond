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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <assert.h>
#include <getopt.h>
#include <string.h>

#include "logactiond.h"

la_runtype_t run_type = LA_UTIL_FOREGROUND;
unsigned int log_level = LOG_DEBUG; /* by default log only stuff < log_level */
unsigned int id_counter = 0;

static char *cfg_filename = NULL;
static char *log_filename = NULL;
static char *rule_name = NULL;

static void
print_usage(void)
{
        fprintf(stderr,
        "Usage: logactiond-checkrule [-c configfile] [-d] [-r rule] [-v] [file]\n");
}

static void
read_options(int argc, char *argv[])
{
        la_debug("read_options()");

        int opt;

        for (;;)
        {
                static struct option long_options[] =
                {
                        {"rule",       required_argument, NULL, 'r'},
                        {"configfile", required_argument, NULL, 'c'},
                        {"debug",      optional_argument, NULL, 'd'},
                        {"verbose",    no_argument,       NULL, 'v'},
                        {0,            0,                 0,    0  }
                };

                int c = getopt_long(argc, argv, "r:c:d::v", long_options, NULL);

                if (c == -1)
                        break;
                
                switch (c)
                {
                        case 'r': 
                                rule_name = optarg;
                                break;
                        case 'c':
                                cfg_filename = optarg;
                                break;
                        case 'd': 
                                log_level++;
                                run_type = LA_UTIL_DEBUG;
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

        la_debug("next_line(%s)", line);

        for (la_pattern_t *pattern = ITERATE_PATTERNS(rule->patterns);
                        pattern = NEXT_PATTERN(pattern);)
        {
                la_debug("pattern %u: %s\n", pattern->num, pattern->string);
                /* TODO: make this dynamic based on detected tokens */
                regmatch_t pmatch[MAX_NMATCH];
                if (!regexec(pattern->regex, line, MAX_NMATCH, pmatch, 0))
                {
                        printf("%s(%u): %s", rule->name, pattern->num, line);
                        if (line[strlen(line)-1] != '\n')
                                printf("\n");
                }
        }
}

static void
iterate_through_all_rules(char *line)
{
        for (la_source_t *source = ITERATE_SOURCES(la_config->sources);
                        source = NEXT_SOURCE(source);)
        {
                for (la_rule_t *rule = ITERATE_RULES(source->rules);
                                rule = NEXT_RULE(rule);)
                {
                        next_line(rule, line);
                }
        }
}

static la_rule_t *
find_rule(const char *rule_name)
{
        for (la_source_t *source = ITERATE_SOURCES(la_config->sources);
                        source = NEXT_SOURCE(source);)
        {
                for (la_rule_t *rule = ITERATE_RULES(source->rules);
                                rule = NEXT_RULE(rule);)
                {
                        if (!strcmp(rule_name, rule->name))
                        {
                                la_debug("find_rule(%s)", rule_name);
                                return rule;
                        }
                }
        }

        la_debug("find_rule(%s)=NULL", rule_name);
        return NULL;
}

int
main(int argc, char *argv[])
{
        FILE *file;

        read_options(argc, argv);

        chdir(CONF_DIR);

        load_la_config(cfg_filename);

        if (log_filename)
        {
                file = fopen(log_filename, "r");
                if (!file)
                        die_err("Opening file \"%s\" failed:", log_filename);
        }
        else
        {
                file = stdin;
        }

        la_rule_t *one_rule = NULL;
        if (rule_name)
                one_rule = find_rule(rule_name);
        

        char *linebuffer = (char *) xmalloc(DEFAULT_LINEBUFFER_SIZE*sizeof(char));
        size_t linebuffer_size = DEFAULT_LINEBUFFER_SIZE*sizeof(char);

        for (;;)
        {
		ssize_t num_read = getline(&linebuffer, &linebuffer_size, file);
		if (num_read==-1)
		{
			if (feof(file))
				break;
			else
                                die_err("Reading from file \"%s\" failed:",
                                                log_filename);
		}
                if (one_rule)
                        next_line(one_rule, linebuffer);
                else
                        iterate_through_all_rules(linebuffer);
        }

        exit(EXIT_SUCCESS);
}


/* vim: set autowrite expandtab: */
