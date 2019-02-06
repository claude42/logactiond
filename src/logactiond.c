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

#include "logactiond.h"

char *cfg_filename = NULL;
char *pid_file = NULL;
bool run_in_foreground = false;
unsigned int log_level = LOG_DEBUG; /* by default log only stuff < log_level */

static void
handle_signal(int signal)
{
        /* printf("Received signal %u\n", signal); */
        empty_end_queue();
        unload_la_config();
        exit(0);
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
        
	signal(SIGCHLD, SIG_IGN);
        /* TODO: take care of SIGHUP */
	signal(SIGHUP, SIG_IGN);

        sigaction(SIGINT, NULL, &old_act);
        if (old_act.sa_handler != SIG_IGN)
                sigaction(SIGINT, &new_act, NULL);
        sigaction(SIGTERM, NULL, &old_act);
        if (old_act.sa_handler != SIG_IGN)
                sigaction(SIGTERM, &new_act, NULL);
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
	//TODO: Implement a working signal handler */
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

	/* Change the working directory to the root directory */
	/* or another appropriated directory */
	chdir(CONF_DIR);

	/* Close all open file descriptors */
	int x;
	for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
	{
		close (x);
	}

	/* Open the log file */
	openlog (NULL, 0, LOG_DAEMON);
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
                        {"version",    no_argument,       NULL, 'v'},
                        {0,            0,                 0,    0  }
                };

                int c = getopt_long(argc, argv, "fc:d::p:v", long_options, NULL);

                if (c == -1)
                        break;
                
                switch (c)
                {
                        case 'f': 
                                run_in_foreground = true;
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
                        case 'v': 
                                break;
                        case '?':
                                printf("Problem\n");
                                break;
                        default:
                                printf("Getop returnd character code %c\n", c);
                                break;

                }
        }
}

int
main(int argc, char *argv[])
{
	int ifd;
	int wd;

	chdir(CONF_DIR);

        read_options(argc, argv);

        if (!run_in_foreground)
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

