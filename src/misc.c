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
#include <err.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "logactiond.h"

bool created_pidfile = false;

void
remove_pidfile(void)
{
        if (created_pidfile)
        {
                if (unlink(PIDFILE) && errno != ENOENT)
                        la_log(LOG_ERR, "Unable to remove pidfile");
        }
        created_pidfile = false;
}

void
create_pidfile(void)
{
        int fd;
        char buf[20]; /* should be enough - I think */
        int len;

        fd = open(PIDFILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd == -1)
                die_err("Unable to open pidfile");

        created_pidfile = true;

        if (ftruncate(fd, 0))
                die_err("Unable to truncate pidfile");

        snprintf(buf, 20, "%ld\n", (long) getpid());
        if (write(fd, buf, len) != len)
                die_err("Unable to write pid to pidfile");

        if (close(fd))
                die_err("Unable to close pidfile");
}

static void
log_message(unsigned int priority, char *fmt, va_list gp, char *add)
{
        if (priority >= log_level ||
                        (run_type == LA_UTIL_FOREGROUND && priority >= LOG_INFO))
                return;

        switch (run_type)
        {
                case LA_DAEMON_BACKGROUND:
                        vsyslog(priority, fmt, gp);
                        // FIXME: must print "add" as well
                        break;
                case LA_DAEMON_FOREGROUND:
                        fprintf(stderr, "<%u>", priority);
                        /* intended fall through! */
                case LA_UTIL_FOREGROUND:
                case LA_UTIL_DEBUG:
                        vfprintf(stderr, fmt, gp);
                        if (add)
                                fprintf(stderr, ": %s", add);
                        fprintf(stderr, "\n");
                        break;
        }
}

time_t
xtime(time_t *tloc)
{
        time_t result = time(tloc);
        if (result == -1)
                die_hard("Can't get time!");

        return result;
}

void xfree(void *ptr)
{
        la_debug("free(%u)", ptr);
        free(ptr);
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
la_log_errno(unsigned int priority, char *fmt, ...)
{
        va_list myargs;

        va_start(myargs, fmt);
        log_message(priority, fmt, myargs, strerror(errno));
        va_end(myargs);
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
die_semantic(char *fmt, ...)
{
        va_list myargs;

        va_start(myargs, fmt);
        log_message(LOG_ERR, fmt, myargs, NULL);
        va_end(myargs);

        shutdown_daemon(EXIT_FAILURE);
}

void
die_hard(char *fmt, ...)
{
        va_list myargs;

        va_start(myargs, fmt);
        log_message(LOG_ERR, fmt, myargs, NULL);
        va_end(myargs);

        shutdown_daemon(EXIT_FAILURE);
}

void
die_err(char *fmt, ...)
{
        va_list myargs;

        va_start(myargs, fmt);
        log_message(LOG_ERR, fmt, myargs, strerror(errno));
        va_end(myargs);

        shutdown_daemon(EXIT_FAILURE);
}

void *
xmalloc(size_t n)
{
        void *result =  malloc(n);
        if (!result && n!=0)
                die_hard("Memory exhausted\n");

        return result;
}

char *
xstrdup(const char *s)
{
        if (!s)
                return NULL;

        void *result = strdup(s);
        if (!result)
                die_hard("Memory exhausted\n");

        return result;
}

char *
xstrndup(const char *s, size_t n)
{
        void *result = strndup(s, n);
        if (!result)
                die_hard("Memory exhausted\n");

        return result;
}

/* vim: set autowrite expandtab: */
