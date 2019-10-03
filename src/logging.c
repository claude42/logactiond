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
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <pthread.h>

#include "logactiond.h"

void
log_message(unsigned int priority, char *fmt, va_list gp, char *add)
{
        assert(fmt);

#ifndef CLIENTONLY
        if (priority >= log_level ||
                        (run_type == LA_UTIL_FOREGROUND && priority >= LOG_INFO))
                return;

        if (priority == LOG_VDEBUG)
                priority = LOG_DEBUG;

        switch (run_type)
        {
                case LA_DAEMON_BACKGROUND:
                        vsyslog(priority, fmt, gp);
                        if (add)
                                syslog(priority, "%s", add);
                        break;
                case LA_DAEMON_FOREGROUND:
                        fprintf(stderr, "<%u>", priority);
                        /* intended fall through! */
                case LA_UTIL_FOREGROUND:
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

void
la_debug(char *fmt, ...)
{
#ifndef NDEBUG
        va_list myargs;

        va_start(myargs, fmt);
        log_message(LOG_DEBUG, fmt, myargs, NULL);
        va_end(myargs);

#endif /* NDEBUG */
}

void
la_vdebug(char *fmt, ...)
{
#ifndef NDEBUG
        va_list myargs;

        va_start(myargs, fmt);
        log_message(LOG_VDEBUG, fmt, myargs, NULL);
        va_end(myargs);

#endif /* NDEBUG */
}

void
la_log_errno(unsigned int priority, char *fmt, ...)
{
        va_list myargs;

        va_start(myargs, fmt);
        log_message(priority, fmt, myargs, strerror(errno));
        va_end(myargs);
}

void
la_log_verbose(unsigned int priority, char *fmt, ...)
{
        va_list myargs;

#ifndef CLIENTONLY
        if (log_verbose)
#endif /* CLIENTONLY */
        {
                va_start(myargs, fmt);
                log_message(priority, fmt, myargs, NULL);
                va_end(myargs);
        }
}

void
la_log(unsigned int priority, char *fmt, ...)
{
        va_list myargs;

        va_start(myargs, fmt);
        log_message(priority, fmt, myargs, NULL);
        va_end(myargs);
}

void
die_hard(char *fmt, ...)
{
        va_list myargs;

        int save_errno = errno;

        va_start(myargs, fmt);
        log_message(LOG_ERR, fmt, myargs, NULL);
        va_end(myargs);

#ifdef CLIENTONLY
        exit(1);
#else  /* CLIENTONLY */
        if (!shutdown_ongoing)
                trigger_shutdown(EXIT_FAILURE, save_errno);

        pthread_exit(NULL);
#endif  /* CLIENTONLY */
}

void
die_err(char *fmt, ...)
{
        va_list myargs;

        int save_errno = errno;

        va_start(myargs, fmt);
        log_message(LOG_ERR, fmt, myargs, strerror(errno));
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
