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
bool shutdown_ongoing = false;
int exit_status = EXIT_SUCCESS;
bool show_undetected = false;

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
        "Usage: logactiond-cleanup [-c configfile] [-d] [-v]\n");
}

static void
read_options(int argc, char *argv[])
{
        la_debug("read_options()");

        for (;;)
        {
                static struct option long_options[] =
                {
                        {"configfile", required_argument, NULL, 'c'},
                        {"debug",      optional_argument, NULL, 'd'},
                        {"verbose",    no_argument,       NULL, 'v'},
                        {0,            0,                 0,    0  }
                };

                int c = getopt_long(argc, argv, "c:d::v", long_options, NULL);

                if (c == -1)
                        break;
                
                switch (c)
                {
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
                                printf("Getopt returnd character code %c\n", c);
                                break;

                }
        }
        if (optind < argc)
                log_filename = argv[optind];
}

int
main(int argc, char *argv[])
{
        FILE *file;

        read_options(argc, argv);

        chdir(CONF_DIR);

        load_la_config(cfg_filename);
        la_debug("done load_la_config()");

        empty_end_queue();


        /* This whole exit procedure doesn't make much sense for a standalone
         * tool. We're just obeying to the infrastructure set in place by the
         * main daemon. */
        trigger_shutdown(EXIT_SUCCESS, 0);

        unload_la_config();
        exit(exit_status);
}


/* vim: set autowrite expandtab: */

