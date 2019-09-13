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
#include <pthread.h>
#include <string.h>
#if HAVE_LIBSYSTEMD
#include <systemd/sd-daemon.h>
#endif /* HAVE_LIBSYSTEMD */

#include "logactiond.h"

char *cfg_filename = NULL;
char *pid_file = NULL;
la_runtype_t run_type = LA_DAEMON_BACKGROUND;
unsigned int log_level = LOG_DEBUG; /* by default log only stuff < log_level */
unsigned int id_counter = 0;
char *run_uid_s = NULL;
unsigned int status_monitoring = 0;
bool shutdown_ongoing = false;
int exit_status = EXIT_SUCCESS;
static int exit_errno = 0;

void
trigger_shutdown(int status, int saved_errno)
{
        la_debug("trigger_shutdown()");
        assert(!shutdown_ongoing);

        exit_status = status;
        exit_errno = saved_errno;
        shutdown_ongoing = true;

        if (file_watch_thread)
                pthread_cancel(file_watch_thread);
#if HAVE_LIBSYSTEMD
        if (systemd_watch_thread)
                pthread_cancel(systemd_watch_thread);
#endif /* HAVE_LIBSYSTEMD */
        if (end_queue_thread)
                pthread_cancel(end_queue_thread);
        if (monitoring_thread)
                pthread_cancel(monitoring_thread);

        pthread_cancel(pthread_self());
}

static void
handle_signal(int signal)
{
        la_debug("handle_signal(%u)", signal);

        if (signal == SIGHUP)
        {
#if HAVE_LIBSYSTEMD
                sd_notify(0, "RELOADING=1\n"
                                "STATUS=Reloading configuration.\n");
#endif /* HAVE_LIBSYSTEMD */
                shutdown_watching();
                unload_la_config();
                load_la_config(cfg_filename);
                update_queue_count_numbers();
                init_watching();
#if HAVE_LIBSYSTEMD
                sd_notify(0, "READY=1\n"
                                "RELOADING=0\n"
                                "STATUS=Configuration reloaded - monitoring log files.\n");
#endif /* HAVE_LIBSYSTEMD */
        }
        else if (signal == SIGUSR1)
        {
                empty_end_queue();
        }
        else
        {
                trigger_shutdown(EXIT_SUCCESS, 0);
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
ignore_sigpipe(void)
{
	struct sigaction act;
	int r;

	memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_IGN;
	act.sa_flags = SA_RESTART;
	r = sigaction(SIGPIPE, &act, NULL);
	if (r)
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
        set_signal(new_act, SIGUSR1);
	ignore_sigpipe();
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
                        {"status",     optional_argument, NULL, 't'},
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
                                status_monitoring++;
                                if (optarg && *optarg == 't')
                                        status_monitoring++;
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

/* Determine UID belonging to what's been specified on the command line. This
 * could be either the UID (as string) itself or as user name.
 */

static uid_t
getrunuid(const char *uid_s)
{
        /* If there's no argument, we assume UID 0 */
        if (!uid_s)
                return 0;
        
        /* Don't accept empty string */
        if (*uid_s == '\0')
                return -1;

        /* First test whether a UID has been specified on the command line. In
         * case endptr points to a 0, the argument was a number. If otherwise
         * there are spurious characters after the number and we don't accept
         * the argument. */
        char *endptr;
        int value = strtol(uid_s,  &endptr, 10);
        if (*endptr == '\0')
                return value;

        /* If its not a number, we test for a username. */
        struct passwd *pw = getpwnam(uid_s);
        if (pw)
                return pw->pw_uid;

        return -1;
}

/* Run with correct UID. Correct if,
 *
 * - Current UID and requested UID are the same.
 * - Current UID is root and setuid() to desired user is succesful.
 *
 * Will die if otherwise.
 *
 */

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

static void
cleanup_main(void *arg)
{
        la_debug("cleanup_main()");

        /* Log that we're going down */
        la_log(LOG_INFO, "Shutting down");

#if HAVE_LIBSYSTEMD
        sd_notifyf(0, "STOPPING=1\n"
                        "STATUS=Exiting (status=%u, errno%u)\n"
                        "ERRNO=%u\n", exit_status, exit_errno, exit_errno);
#endif /* HAVE_LIBSYSTEMD */

        /* Wait for all threads to end */
        if (end_queue_thread)
                xpthread_join(end_queue_thread, NULL);
        la_debug("joined end_queue_thread");

        if (monitoring_thread)
                xpthread_join(monitoring_thread, NULL);
        la_debug("joined status_monitoring_thread");

        if (file_watch_thread)
                xpthread_join(file_watch_thread, NULL);
        la_debug("joined file_watch_thread");

#if HAVE_LIBSYSTEMD
        if (systemd_watch_thread)
                xpthread_join(systemd_watch_thread, NULL);
        la_debug("joined systemd_watch_thread");
#endif /* HAVE_LIBSYSTEMD */

        unload_la_config();
#ifndef NOCOMMANDS
        free_meta_command_list(la_config->meta_list);
#endif /* NOCOMMANDS */

        /* TODO: not the best place here but well */
        free(la_config);
        la_config = NULL;

        remove_pidfile();
        int loglevel = exit_status ? LOG_WARNING : LOG_INFO;
        la_log(loglevel, "Exiting (status=%u, errno=%u).", exit_status, exit_errno);

        exit(exit_status);
}

int
main(int argc, char *argv[])
{
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

        pthread_cleanup_push(cleanup_main, NULL);

        la_log(LOG_INFO, "Starting up " PACKAGE_STRING ".");

        start_end_queue_thread();
        load_la_config(cfg_filename);
        start_watching_threads();
        start_monitoring_thread();

#if HAVE_LIBSYSTEMD
        sd_notify(0, "READY=1\n"
                        "STATUS=logactiond started - monitoring log files.\n");
#endif /* HAVE_LIBSYSTEMD */

        la_debug("Main thread going to sleep.");

        /* Wait forever - until thread gets pthread_cancell()ed */
        while (sleep(INT_MAX))
                la_debug("Sleep interrupted, going back to sleep");

        /* We must have waited for a LONG time to get here... :-) */
        assert(false);
        /* Will never be reached, simple here to make potential pthread macros
         * happy */
        pthread_cleanup_pop(1);
}



/* vim: set autowrite expandtab: */

