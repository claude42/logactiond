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
#include <unistd.h>
#include <stdlib.h>
#include <sys/select.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <signal.h>
#include <assert.h>
#include <getopt.h>
#if HAVE_INOTIFY
#include <sys/inotify.h>
#endif /* HAVE_INOTIFY */

#include "logactiond.h"

char *cfg_filename = NULL;
char *pid_file = NULL;
la_runtype_t run_type = LA_DAEMON_BACKGROUND;
unsigned int log_level = LOG_DEBUG; /* by default log only stuff < log_level */
unsigned int id_counter = 0;

void
shutdown_daemon(int status)
{
        /* TODO: once we have multiple threads watching sources, must ensure
         * that threads are stopped before continuing */
        empty_end_queue();
        unload_la_config();
        remove_pidfile();
        exit(status);
}

static void
handle_signal(int signal)
{
        la_debug("handle_signal(%u)", signal);
        /* printf("Received signal %u\n", signal); */

        if (signal == SIGHUP)
        {
                // disabled for now as it doesn't work correctly
                //empty_end_queue();
                //unload_la_config();
                //load_la_config(cfg_filename);
        }
        else
        {
                shutdown_daemon(EXIT_SUCCESS);
        }
}

static void
register_signal_handler(void)
{
        la_debug("register_signal_handler()");

        struct sigaction new_act;
        struct sigaction old_act;

        new_act.sa_handler = handle_signal;
        sigemptyset(&new_act.sa_mask);
        new_act.sa_flags = 0;

        sigaction(SIGINT, NULL, &old_act);
        if (old_act.sa_handler != SIG_IGN)
                sigaction(SIGINT, &new_act, NULL);
        sigaction(SIGTERM, NULL, &old_act);
        if (old_act.sa_handler != SIG_IGN)
                sigaction(SIGTERM, &new_act, NULL);
        sigaction(SIGHUP, NULL, &old_act);
        if (old_act.sa_handler != SIG_IGN)
                sigaction(SIGHUP, &new_act, NULL);
}

/*
 * Taken from Pascal Werkl's answer to
 * https://stackoverflow.com/questions/17954432/creating-a-daemon-in-linux#17955149
 */

static void
skeleton_daemon(void)
{
        la_debug("skeleton_daemon()");

        pid_t pid;

        /* Fork off the parent process */
        pid = fork();

        /* An error occurred */
        if (pid < 0)
                exit(EXIT_FAILURE);

        /* Success: Let the parent terminate */
        if (pid > 0)
                exit(EXIT_SUCCESS);

        /* On success: The child process becomes session leader */
        if (setsid() < 0)
                exit(EXIT_FAILURE);

        /* Catch, ignore and handle signals */
        signal(SIGCHLD, SIG_IGN);
        register_signal_handler();

        /* Fork off for the second time*/
                pid = fork();

        /* An error occurred */
        if (pid < 0)
                exit(EXIT_FAILURE);

        /* Success: Let the parent terminate */
        if (pid > 0)
                exit(EXIT_SUCCESS);

        /* Set new file permissions */
        umask(0);

        /* Change the working directory */
        chdir(CONF_DIR);

        /* Close all open file descriptors */
        int x;
        for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
        {
                close (x);
        }

        /* create pidfile */
        create_pidfile();

        /* Open the log file */
        openlog(NULL, LOG_PID, LOG_DAEMON);
}

static void
print_usage(void)
{
        fprintf(stderr,
                "Usage: logactiond [-c configfile] [-d] [-f] [-p pidfile] [-s]\n");
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
                        {"foreground", no_argument,       NULL, 'f'},
                        {"configfile", required_argument, NULL, 'c'},
                        {"debug",      optional_argument, NULL, 'd'},
                        {"pidfile",    required_argument, NULL, 'p'},
                        {"simulate",   no_argument,       NULL, 's'},
                        {0,            0,                 0,    0  }
                };

                int c = getopt_long(argc, argv, "fc:d::p:s", long_options, NULL);

                if (c == -1)
                        break;
                
                switch (c)
                {
                        case 'f': 
                                run_type = LA_DAEMON_FOREGROUND;
                                break;
                        case 'c':
                                cfg_filename = optarg;
                                break;
                        case 'd': 
                                log_level++;
                                if (optarg && *optarg == 'd')
                                        log_level++;
                                break;
                        case 'p':
                                pid_file = optarg;
                                break;
                        case 's': 
                                run_type = LA_UTIL_FOREGROUND;
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
}

/*
 * Abstract event loop
 */

void
watch_forever(void)
{
        la_debug("watch_forever()");
#ifndef NOWATCH
#if HAVE_INOTIFY
        watch_forever_inotify();
#endif /* HAVE_INOTIFY */
#endif /* NOWATCH */
}

/*
 * Do all steps necessary before files can be watched. Depending on the method
 * used, no such steps might be necessary at all.
 */

void
init_watching(void)
{
        la_debug("init_watching()");

#ifndef NOWATCH
#if HAVE_INOTIFY
        init_watching_inotify();
#else /* HAVE_INOTIFY */
        die_hard("Don't have inotify!");
#endif /* HAVE_INOTIFY */
#endif /* NOWATCH */
}

int
main(int argc, char *argv[])
{
        int ifd;
        int wd;

        chdir(CONF_DIR);

        read_options(argc, argv);

        if (run_type == LA_UTIL_FOREGROUND)
        {
                load_la_config(cfg_filename);
                unload_la_config();
                fprintf(stderr, "Simulation successful.\n");
                exit(EXIT_SUCCESS);
        }

        la_log(LOG_INFO, "Starting up " PACKAGE_STRING);

        if (run_type == LA_DAEMON_BACKGROUND)
                skeleton_daemon();
        else
                register_signal_handler();

        init_end_queue();
        init_watching();

        load_la_config(cfg_filename);

        watch_forever();

        assert(false);
}



/* vim: set autowrite expandtab: */

