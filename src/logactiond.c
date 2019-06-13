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
#include <pwd.h>
#include <limits.h>
#if HAVE_INOTIFY
#include <sys/inotify.h>
#endif /* HAVE_INOTIFY */

#include "logactiond.h"

char *cfg_filename = NULL;
char *pid_file = NULL;
la_runtype_t run_type = LA_DAEMON_BACKGROUND;
unsigned int log_level = LOG_DEBUG; /* by default log only stuff < log_level */
unsigned int id_counter = 0;
char *run_uid_s = NULL;
bool status_monitoring = false;
bool shutdown_ongoing = false;
int exit_status = EXIT_SUCCESS;

void
shutdown_daemon(int status)
{
        /* TODO: once we have multiple threads watching sources, must ensure
         * that threads are stopped before continuing */
        exit_status = status;
        shutdown_ongoing = true;
        shutdown_watching();
        empty_end_queue();
        shutdown_monitoring();
        unload_la_config();
        remove_status_files();
        remove_pidfile();
        la_debug("shutdown_daemon() ending");
}

static void
handle_signal(int signal)
{
        la_log(LOG_NOTICE, "Received signal %u", signal);

        if (signal == SIGHUP)
        {
#if HAVE_LIBSYSTEMD
                sd_notify(0, "RELOADING=1\n"
                                "STATUS=Reloading configuration.\n");
#endif /* HAVE_LIBSYSTEMD */
                shutdown_watching();
                empty_end_queue();
                unload_la_config();
                load_la_config(cfg_filename);
                init_watching();
#if HAVE_LIBSYSTEMD
                sd_notify(0, "READY=1\n"
                                "RELOADING=0\n"
                                "STATUS=Configuration reloaded - monitoring log files.\n");
#endif /* HAVE_LIBSYSTEMD */
        }
        else if (signal == SIGPIPE)
        {
                for (int x = sysconf(_SC_OPEN_MAX); x>=0; x--)
                {
                        close (x);
                }
                exit(0);
                log_level = 0;
                shutdown_daemon(EXIT_SUCCESS);
        }
        else
        {
                shutdown_daemon(EXIT_SUCCESS);
        }
}

static void
set_signal(struct sigaction new_act, int signum)
{
        struct sigaction old_act;

        if (sigaction(signum, NULL, &old_act) == -1)
                die_err("Error setting signals!");
        if (old_act.sa_handler != SIG_IGN)
                if (sigaction(signum, &new_act, NULL) == -1)
                        die_err("Error setting signals!");

}

static void
register_signal_handler(void)
{
        la_debug("register_signal_handler()");

        struct sigaction new_act;

        new_act.sa_handler = handle_signal;
        if (sigemptyset(&new_act.sa_mask) == -1)
                die_err("Error setting signals!");
        new_act.sa_flags = 0;

        set_signal(new_act, SIGINT);
        set_signal(new_act, SIGTERM);
        set_signal(new_act, SIGHUP);
        set_signal(new_act, SIGPIPE);
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
        (void) umask(0);

        /* Change the working directory */
        if (chdir(CONF_DIR) == -1)
                die_err("Can't change to configuration directory!");

        /* Close all open file descriptors */
        int x;
        for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
        {
                close (x);
        }

        /* create pidfile */
        create_pidfile();

        /* Open the log file */
        openlog(SYSLOG_IDENT, LOG_PID, LOG_DAEMON);
}

static void
print_usage(void)
{
        fprintf(stderr,
                "Usage: logactiond [-c configfile] [-d] [-f] [-p pidfile] [-s] [-t]\n");
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
                        {"user",       required_argument, NULL, 'u'},
                        {"status",     no_argument,       NULL, 't'},
                        {0,            0,                 0,    0  }
                };

                int c = getopt_long(argc, argv, "fc:d::p:su:t", long_options, NULL);

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
                        case 'u':
                                run_uid_s = optarg;
                                break;
                        case 't':
                                status_monitoring = true;
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

static uid_t
getrunuid(const char *uid_s)
{
        if (!uid_s)
                return 0;

        char *endptr;
        int value = strtol(uid_s,  &endptr, 10);
        if (endptr != uid_s)
                return value;

        struct passwd *pw = getpwnam(uid_s);
        if (pw)
                return pw->pw_uid;

        return -1;
}

static void
use_correct_uid(void)
{
        uid_t cur_uid = geteuid();
        uid_t run_uid = getrunuid(run_uid_s);
        if (run_uid == -1)
                die_hard("Can't determine uid!");

        la_debug("use_correct_uid() - uid=%d, runuid=%d", cur_uid, run_uid);

        if (cur_uid == run_uid)
                return;

        if (!cur_uid)
        {
                if (!setuid(run_uid))
                        return;
                else
                        die_err("Can't change to \"%s\".", run_uid_s);
        }
        else
        {
                if (run_uid_s)
                        die_hard("Can't change uid for non-root user.");
                else
                        die_hard("Trying to run as non-root user.");
        }
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

        use_correct_uid();

        if (run_type == LA_DAEMON_BACKGROUND)
                skeleton_daemon();
        else
                register_signal_handler();

        la_log(LOG_INFO, "Starting up " PACKAGE_STRING);

        init_end_queue();
        load_la_config(cfg_filename);

        init_watching();
        init_queue_processing();
        init_monitoring();

        la_debug("Main thread going to sleep.");

        pthread_join(watch_thread, NULL);
        pthread_join(end_queue_thread, NULL);
        if (status_monitoring)
                pthread_join(monitoring_thread, NULL);

        exit(exit_status);
}



/* vim: set autowrite expandtab: */

