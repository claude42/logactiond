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
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <getopt.h>
#include <pwd.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#if HAVE_LIBSYSTEMD
#include <systemd/sd-daemon.h>
#endif /* HAVE_LIBSYSTEMD */
#include <stdbool.h>
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
#endif /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */

#include "ndebug.h"
#include "addresses.h"
#include "commands.h"
#include "configfile.h"
#include "endqueue.h"
#include "fifo.h"
#include "logactiond.h"
#include "logging.h"
#include "messages.h"
#include "misc.h"
#include "remote.h"
#include "state.h"
#include "status.h"
#if HAVE_LIBSYSTEMD
#include "systemd.h"
#endif /* HAVE_LIBSYSTEMD */
#include "watch.h"
#include "nodelist.h"
#include "binarytree.h"
#include "crypto.h"
#include "metacommands.h"
#include "pthread_barrier.h"

pthread_t main_thread = 0;
pthread_barrier_t final_barrier;
bool barrier_initialized = false;
/* num_threads not declared as atomic because only main thread ever modifies it
 */
int num_threads = 1;

char *cfg_filename = NULL;
char *pid_file = NULL;
la_runtype_t run_type = LA_DAEMON_BACKGROUND;
char *run_uid_s = NULL;
bool create_backup_file = false;
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
        atomic_bool shutdown_ongoing = ATOMIC_VAR_INIT(false);
#else /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */
        bool shutdown_ongoing = false;
#endif /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */
int exit_status = EXIT_SUCCESS;
static int exit_errno = 0;
bool sync_on_startup = false;

void
trigger_shutdown(int status, int saved_errno)
{
        la_debug_func(NULL);
        if (shutdown_ongoing)
        {
                la_log(LOG_ERR, "triggered shutdown when shutdown already ongoing!");
                return;
        }

        exit_status = status;
        exit_errno = saved_errno;
        shutdown_ongoing = true;

        la_log(LOG_INFO, "Shutting down");

#if HAVE_LIBSYSTEMD
        sd_notifyf(0, "STOPPING=1\n"
                        "STATUS=Exiting (status=%u, errno%u)\n"
                        "ERRNO=%u\n", exit_status, exit_errno, exit_errno);
#endif /* HAVE_LIBSYSTEMD */

        save_state(true);

        xpthread_cancel_if_applicable(file_watch_thread);
#if HAVE_LIBSYSTEMD
        xpthread_cancel_if_applicable(systemd_watch_thread);
#endif /* HAVE_LIBSYSTEMD */
        xpthread_cancel_if_applicable(end_queue_thread);
#ifndef NOMONITORING
        xpthread_cancel_if_applicable(monitoring_thread);
#endif /* NOMONITORING */
        xpthread_cancel_if_applicable(fifo_thread);
        cancel_all_remote_threads();
        xpthread_cancel_if_applicable(save_state_thread);

        /* Apparently signals are delivered to a random thread, so
         * - if signal has been catched by main thread simply return and don't
         *   pthread_exit() as main thread still has some things to do after
         *   all other threads have exited.
         *   - special case: if barrier never has been initialized an error has
         *     happend early on, then simply bail out via exit()
         * - OTOH if it's any other thread, call pthread_exit() because
         *   cancelling oneself (in one of the lines above) would have been a
         *   bad idea */

        if (pthread_equal(pthread_self(), main_thread))
        {
                if (barrier_initialized)
                        return;
                else
                        exit(1);
        }
        else
        {
                pthread_exit(NULL);
        }
}

void
trigger_reload(void)
{
                /* TODO: must do more, e.g. shutdown remote thread in case
                 * configuration changes apply to it */
                if (init_la_config(cfg_filename))
                {
#if HAVE_LIBSYSTEMD
                        sd_notify(0, "RELOADING=1\n"
                                        "STATUS=Reloading configuration.\n");
#endif /* HAVE_LIBSYSTEMD */
                        shutdown_watching();
                        unload_la_config();
                        load_la_config();
                        update_queue_count_numbers();
                        init_watching();
#if HAVE_LIBSYSTEMD
                        sd_notify(0, "READY=1\n"
                                        "RELOADING=0\n"
                                        "STATUS=Configuration reloaded - monitoring log files.\n");
#endif /* HAVE_LIBSYSTEMD */
                }
}

static void
handle_signal(const int signal)
{
        la_debug("handle_signal(%i)", signal);

        switch (signal)
        {
        case SIGHUP:
                trigger_reload();
                break;
        case SIGUSR1:
                empty_end_queue();
                break;
        case SIGINT:
        case SIGTERM:
                trigger_shutdown(EXIT_SUCCESS, 0);
                break;
        case SIGABRT:
                la_log(LOG_ERR, "Process aborted");
                trigger_shutdown(EXIT_FAILURE, 0);
                break;
        default:
                la_log(LOG_ERR, "Received unknown signal %u", signal);
                trigger_shutdown(EXIT_FAILURE, 0);
                break;
        }

}

static void
set_signal(struct sigaction new_act, const int signum)
{
        struct sigaction old_act;

        if (sigaction(signum, NULL, &old_act) == -1)
                die_hard(true, "Error setting signals");
        if (old_act.sa_handler != SIG_IGN)
                if (sigaction(signum, &new_act, NULL) == -1)
                        die_hard(true, "Error setting signals");

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
		die_hard(true, "Error setting signals");
}

static void
register_signal_handler(void)
{
        la_debug_func(NULL);

        struct sigaction new_act;

        new_act.sa_handler = handle_signal;
        if (sigemptyset(&new_act.sa_mask) == -1)
                die_hard(true, "Error setting signals");
        new_act.sa_flags = 0;

        set_signal(new_act, SIGINT);
        set_signal(new_act, SIGTERM);
        set_signal(new_act, SIGHUP);
        set_signal(new_act, SIGABRT); /* for failed assert()s */
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
        la_debug_func(NULL);

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
                die_hard(true, "Can't change to configuration directory");

        /* Close all open file descriptors */
        int x;
        for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
        {
                close (x);
        }

        /* Open the log file */
        openlog(SYSLOG_IDENT, LOG_PID, LOG_DAEMON);
}

static void
print_usage(void)
{
        fprintf(stderr,
                "Usage: logactiond [-c configfile] [-d] [-v] [-f] [-p pidfile] [-t] [-s]\n");
}

static void
read_options(int argc, char *argv[])
{
        la_debug_func(NULL);

        for (;;)
        {
                static struct option long_options[] =
                {
                        {"foreground", no_argument,       NULL, 'f'},
                        {"configfile", required_argument, NULL, 'c'},
                        {"debug",      optional_argument, NULL, 'd'},
                        {"verbose",    no_argument,       NULL, 'v'},
                        {"pidfile",    required_argument, NULL, 'p'},
                        {"user",       required_argument, NULL, 'u'},
                        {"status",     optional_argument, NULL, 't'},
                        {"restore",    optional_argument, NULL, 'r'},
                        {"backup",     no_argument,       NULL, 'b'},
                        {"sync",       no_argument,       NULL, 's'},
                        {0,            0,                 0,    0  }
                };

                /* TODO: two colons seem to be a GNU extension?! */
                int c = getopt_long(argc, argv, "fc:d::vp:u:t::r::bs", long_options, NULL);

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
                        case 'v':
                                log_verbose = true;
                                break;
                        case 'p':
                                pid_file = optarg;
                                break;
                        case 'u':
                                run_uid_s = optarg;
                                break;
                        case 't':
                                status_monitoring++;
                                if (optarg && *optarg == 't')
                                        status_monitoring++;
                                break;
                        case 'r':
                                if (optarg)
                                        set_saved_state(optarg);
                                else
                                        set_saved_state(STATE_DIR "/"
                                                        STATE_FILE);
                                break;
                        case 'b':
                                create_backup_file = true;
                                break;
                        case 's':
                                sync_on_startup = true;
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

/* TODO: maybe move this to remote.c */

static void
sync_with_other_instances(void)
{
        la_debug_func(NULL);
        /* make sure remote thread is already set up and running */
        sleep(1);

        assert(la_config);
#ifdef WITH_LIBSODIUM
        generate_send_key_and_salt(la_config->remote_secret);
#endif /* WITH_LIBSODIUM */

        char message[TOTAL_MSG_LEN];
        if (!init_sync_message(message, NULL))
                LOG_RETURN(, LOG_ERR, "Unable to create sync message");
#ifdef WITH_LIBSODIUM
        if (!encrypt_message(message))
                LOG_RETURN(, LOG_ERR, "Unable to encrypt sync message");
#endif /* WITH_LIBSODIUM */

        send_message_to_all_remote_hosts(message);
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
        const uid_t cur_uid = geteuid();
        const uid_t run_uid = determine_uid(run_uid_s);
        if (run_uid == UINT_MAX)
                die_hard(false, "Can't determine uid!");

        la_debug("use_correct_uid() - uid=%d, runuid=%d", cur_uid, run_uid);

        if (cur_uid == run_uid)
                return;

        if (!cur_uid)
        {
                if (!setuid(run_uid))
                        return;
                else
                        die_hard(true, "Can't change to \"%s\"", run_uid_s);
        }
        else
        {
                if (run_uid_s)
                        die_hard(false, "Can't change uid for non-root user.");
                else
                        die_hard(false, "Trying to run as non-root user.");
        }
}

int
main(int argc, char *argv[])
{
        inject_misc_exit_function(die_hard);
        inject_nodelist_exit_function(die_hard);
        inject_binarytree_exit_function(die_hard);

        if (chdir(CONF_DIR) == -1)
                die_hard(true, "Can't change to configuration directory");

        read_options(argc, argv);

        if (check_pidfile(PIDFILE))
                die_hard(false, "logactiond already running!");

        use_correct_uid();

        if (run_type == LA_DAEMON_BACKGROUND)
                skeleton_daemon();
        else
                register_signal_handler();

        create_pidfile(PIDFILE);

        main_thread = pthread_self();

        la_log(LOG_INFO, "Starting up " PACKAGE_STRING ".");

        init_end_queue();
        if (!init_la_config(cfg_filename))
                die_hard(false, "Error loading configuration.");
        load_la_config();

        start_watching_threads();
#ifndef NOMONITORING
        start_monitoring_thread();
#endif /* NOMONITORING */
        start_fifo_thread();
        start_all_remote_threads();

        restore_state_and_start_save_state_thread(create_backup_file);

        start_end_queue_thread();

        if (sync_on_startup)
        {
                if (la_config->remote_enabled)
                        sync_with_other_instances();
                else
                        die_hard(false, "Remote sync requested but remote "
                                        "communication not enabled!");
        }

#if HAVE_LIBSYSTEMD
        sd_notify(0, "READY=1\n"
                        "STATUS=logactiond started - monitoring log files.\n");
#endif /* HAVE_LIBSYSTEMD */

        if (!shutdown_ongoing)
        {
                pthread_barrier_init(&final_barrier, NULL, num_threads);
                barrier_initialized = true;
                la_debug("Main thread going to sleep");
                pthread_barrier_wait(&final_barrier);
                pthread_barrier_destroy(&final_barrier);
        }

        unload_la_config();
#if !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS)
        free_meta_list();  // TODO: probably should go somewhere else
#endif /* !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS) */

        if (!remove_pidfile(PIDFILE))
                la_log_errno(LOG_ERR, "Unable to remove pidfile");

        const int loglevel = exit_status ? LOG_WARNING : LOG_INFO;
        la_log(loglevel, "Exiting (status=%u, errno=%u).", exit_status, exit_errno);

        exit(exit_status);
}

void
thread_started(void)
{
        num_threads++;
}

void
wait_final_barrier(void)
{
        la_vdebug_func(barrier_initialized ? "true" : "false");

        if (barrier_initialized)
                pthread_barrier_wait(&final_barrier);
}



/* vim: set autowrite expandtab: */

