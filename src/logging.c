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

#define _GNU_SOURCE
#include <pthread.h>
#if HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif /* HAVE_PTHREAD_NP_H */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <stdnoreturn.h>
#if HAVE_LIBSYSTEMD
#include <systemd/sd-journal.h>
#endif /* HAVE_LIBSYSTEMD */
#include <time.h>

#include "ndebug.h"
#include "logactiond.h"
#include "logging.h"

int log_level = LOG_DEBUG; /* by default log only stuff < log_level */
bool log_verbose = false;

void
log_message(int priority, const char *const add, const char *const fmt, ...)
{
        assert(fmt);

        va_list myargs;

        va_start(myargs, fmt);

        log_message_va_list(priority, fmt, myargs, add);

        va_end(myargs);
}

void
log_message_va_list(int priority, const char *const fmt, va_list gp,
                const char *const add)
{
        assert(fmt);


#ifndef CLIENTONLY
#if HAVE_PTHREAD_GETNAME_NP
#define THREAD_NAME_LEN 16
        char thread_name[THREAD_NAME_LEN];
        if (pthread_getname_np(pthread_self(), thread_name, THREAD_NAME_LEN))
                snprintf(thread_name, THREAD_NAME_LEN, "unnamed");
#endif /* HAVE_PTHREAD_GENTAME_NP */

        if (priority >= log_level ||
                        (run_type == LA_UTIL_FOREGROUND && priority >= LOG_INFO))
                return;

        if (priority == LOG_VDEBUG)
                priority = LOG_DEBUG;

        switch (run_type)
        {
                case LA_DAEMON_BACKGROUND:
#if HAVE_LIBSYSTEMD
                        sd_journal_printv(priority, fmt, gp);
                        if (add)
                                sd_journal_print(priority, "%s", add);
#else /* HAVE_LIBSYSTEMD */
                        vsyslog(priority, fmt, gp);
                        if (add)
                                syslog(priority, "%s", add);
#endif /* HAVE_LIBSYSTEMD */
                        break;
                case LA_DAEMON_FOREGROUND:
                        /* TODO: use flockfile() around all the separate printf
                         * statements */
                        fprintf(stderr, "<%i> %u:", priority, time(NULL));
                        /* intentional fall through! */
                case LA_UTIL_FOREGROUND:
#if HAVE_PTHREAD_GETNAME_NP
                        if (priority == LOG_DEBUG)
                                fprintf(stderr, "%s: ", thread_name);
#endif /* HAVE_PTHREAD_GETNAME_NP */
#endif /* CLIENTONLY */
                        vfprintf(stderr, fmt, gp);
                        if (add)
                                fprintf(stderr, ": %s", add);
                        fprintf(stderr, "\n");
#ifndef CLIENTONLY
                        break;
        }
#endif /* CLIENTONLY */
}

noreturn void
die_hard(const bool log_strerror, const char *const fmt, ...)
{
        va_list myargs;

#ifndef CLIENTONLY
        int save_errno = errno;
#endif /* CLIENTONLY */

        va_start(myargs, fmt);
        log_message_va_list(LOG_ERR, fmt, myargs, log_strerror ? strerror(errno) :
                        NULL);
        va_end(myargs);

#ifdef CLIENTONLY
        exit(1);
#else  /* CLIENTONLY */
        if (!shutdown_ongoing)
                trigger_shutdown(EXIT_FAILURE, save_errno);

        pthread_exit(NULL);
#endif  /* CLIENTONLY */
}

/* vim: set autowrite expandtab: */
