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

#include "logactiond.h"

extern bool run_in_foreground;

static void
log_message(int priority, char *fmt, va_list gp, char *add)
{
        if (priority >= log_level)
                return;

        if (run_in_foreground)
        {
                fprintf(stderr, "<%u>", priority);
                vfprintf(stderr, fmt, gp);
                if (add)
                        fprintf(stderr, ": %s", add);
                fprintf(stderr, "\n");
        }
        else
        {
                vsyslog(priority, fmt, gp);
                // FIXME: must print "add" as well
        }
}

void xfree(void *ptr)
{
        la_debug("FREED %u\n", ptr);
        free(ptr);
}

void
la_debug(char *fmt, ...)
{
#ifndef NDEBUG
        va_list myargs;

        va_start(myargs, fmt);
        log_message(LOG_VDEBUG, fmt, myargs, NULL);
        va_end(myargs);

#endif /* NDEBUG */
}

void
la_log_errno(int priority, char *fmt, ...)
{
        va_list myargs;

        va_start(myargs, fmt);
        log_message(priority, fmt, myargs, strerror(errno));
        va_end(myargs);
}

void
la_log(int priority, char *fmt, ...)
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

        unload_la_config();
        exit(EXIT_FAILURE);
}

void
die_hard(char *fmt, ...)
{
        va_list myargs;

        va_start(myargs, fmt);
        log_message(LOG_ERR, fmt, myargs, NULL);
        va_end(myargs);

        unload_la_config();
        exit(EXIT_FAILURE);
}

void
die_err(char *fmt, ...)
{
        va_list myargs;

        va_start(myargs, fmt);
        log_message(LOG_ERR, fmt, myargs, strerror(errno));
        va_end(myargs);

        unload_la_config();
        exit(EXIT_FAILURE);
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
