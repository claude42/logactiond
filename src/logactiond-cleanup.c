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
#include <errno.h>
#include <stdbool.h>
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
#endif /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */

#include "ndebug.h"
#include "configfile.h"
#include "endqueue.h"
#include "fifo.h"
#include "logactiond.h"
#include "logging.h"
#include "misc.h"
#include "status.h"
#include "nodelist.h"
#include "binarytree.h"

la_runtype_t run_type = LA_UTIL_FOREGROUND;

static char *cfg_filename = NULL;
static char *log_filename = NULL;
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
        atomic_bool shutdown_ongoing = false;
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
        "Usage: logactiond-cleanup [-c configfile] [-d] [-v]\n");
}

static void
read_options(int argc, char *argv[])
{
        la_debug_func(NULL);

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
        inject_misc_exit_function(die_hard);
        inject_nodelist_exit_function(die_hard);
        inject_binarytree_exit_function(die_hard);

        read_options(argc, argv);

        if (chdir(CONF_DIR) == -1)
                die_hard(true, "Can't change to configuration directory");

        init_end_queue();
        if (!init_la_config(cfg_filename))
                die_hard(false, "Error loading configuration");
        load_la_config();
        la_debug("done load_la_config()");

        empty_end_queue();

        if (remove(PIDFILE) && errno != ENOENT)
                la_log_errno(LOG_ERR, "Unable to remove pidfile");
        if (remove(HOSTSFILE) && errno != ENOENT)
                la_log_errno(LOG_ERR, "Can't remove host status file");
        if (remove(RULESFILE) && errno != ENOENT)
                la_log_errno(LOG_ERR, "Can't remove rule status file");
        if (remove(DIAGFILE) && errno != ENOENT)
                la_log_errno(LOG_ERR, "Can't remove diagnostics file");
        if (remove(la_config->fifo_path) && errno != ENOENT)
                la_log_errno(LOG_ERR, "Cannot remove fifo");

        /* This whole exit procedure doesn't make much sense for a standalone
         * tool. We're just obeying to the infrastructure set in place by the
         * main daemon. */
        trigger_shutdown(EXIT_SUCCESS, 0);

        unload_la_config();
        exit(exit_status);
}


/* vim: set autowrite expandtab: */

