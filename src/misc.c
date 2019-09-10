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

#define _GNU_SOURCE
#include <pthread.h>
#if HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif /* HAVE_PTHREAD_NP_H */
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
        la_debug("remove_pidfile()");

        if (created_pidfile)
        {
                if (unlink(PIDFILE) && errno != ENOENT)
                        la_log(LOG_ERR, "Unable to remove pidfile");
                created_pidfile = false;
        }
}

void
create_pidfile(void)
{
        la_debug("create_pidfile(" PIDFILE ")");

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

/*
 * Create thread, die if it fails
 */

void
xpthread_create(pthread_t *thread, const pthread_attr_t *attr,
                void *(*start_routine)(void *), void *arg, char *name)
{
        if (pthread_create(thread, attr, start_routine, arg))
                die_err("Failed to create thread!");
#if HAVE_PTHREAD_SETNAME_NP
        if (pthread_setname_np(*thread, name))
                die_err("Failed to set thread name!");
#elif HAVE_PTHREAD_SET_NAME_NP
        pthread_set_name_np(*thread, name);
#endif
}

/*
 * Wait for condition, die if pthread_cond_wait() fails
 */

void
xpthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
        if (pthread_cond_wait(cond, mutex))
                die_err("Failed to wait for condition!");
}

/*
 * Wait for condition, die if pthread_cond_timedwait() fails
 */

void
xpthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                const struct timespec *abstime)
{
        int ret = pthread_cond_timedwait(cond, mutex, abstime);
        la_vdebug("xpthread_cond_timedwait()=%u", ret);

        switch (ret)
        {
                case 0:
                        break;
                case ETIMEDOUT:
                        la_vdebug("pthread_cond_timedwait() timed out");
                        break;
                case EINTR:
                        la_vdebug("pthread_cond_timedwait() interrupted");
                        break;
                default:
                        die_err("Failed to timed wait for condition");
                        break;
        }
}

/*
 * Signal condition, die if it fails
 */

void
xpthread_cond_signal(pthread_cond_t *cond)
{
        if (pthread_cond_signal(cond))
                die_err("Failed to signal thread!");
}

/*
 * Lock mutex, die if pthread_mutex_lock() fails
 */

void
xpthread_mutex_lock(pthread_mutex_t *mutex)
{
        if (pthread_mutex_lock(mutex))
                die_err("Failed to lock mutex!");
}

/*
 * Unlock mutex, die if pthread_mutex_lock() fails
 */

void
xpthread_mutex_unlock(pthread_mutex_t *mutex)
{
        if (pthread_mutex_unlock(mutex))
                die_err("Failed to unlock mutex!");
}

/* join thread, die if pthread_join() fails
 */

void
xpthread_join(pthread_t thread, void **retval)
{
        if (pthread_join(thread, retval) && errno)
                die_err("Failed to join thread!");
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
log_message(unsigned int priority, char *fmt, va_list gp, char *add)
{
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
                case LA_UTIL_DEBUG:
                        vfprintf(stderr, fmt, gp);
                        if (add)
                                fprintf(stderr, ": %s", add);
                        fprintf(stderr, "\n");
                        break;
        }
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

        if (!shutdown_ongoing)
        {
                trigger_shutdown(EXIT_FAILURE, save_errno);
                pthread_exit(NULL);
        }
        else
        {
                exit(EXIT_FAILURE);
        }
}

void
die_err(char *fmt, ...)
{
        va_list myargs;

        int save_errno = errno;

        va_start(myargs, fmt);
        log_message(LOG_ERR, fmt, myargs, strerror(errno));
        va_end(myargs);

        if (!shutdown_ongoing)
        {
                trigger_shutdown(EXIT_FAILURE, save_errno);
                pthread_exit(NULL);
        }
        else
        {
                exit(EXIT_FAILURE);
        }
}

void *
xrealloc(void *ptr, size_t n)
{
        void *result = realloc(ptr, n);
        if (!result && n!=0)
                die_hard("Memory exhausted");

        return result;
}

void *
xmalloc0(size_t n)
{
        void *result = calloc(n, 1);
        if (!result && n!=0)
                die_hard("Memory exhausted");

        return result;
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

size_t
xstrlen(const char *s)
{
        if (s)
                return strlen(s);
        else
                return 0;
}

/*
 * Concatenates the two strings and creates a newly malloc()ed string. If
 * one string is NULL, returns a duplicate of the other string. If both are
 * NULL, returns NULL.
 */

char *
concat(const char *s1, const char *s2)
{
        if (!s1)
                return xstrdup(s2);
        if (!s2)
                return xstrdup(s1);

        size_t len1 = strlen(s1);
        size_t len2 = strlen(s2);
        char *result = xmalloc(len1 + len2 + 1);

        memcpy(result, s1, len1);
        memcpy(result + len1, s2, len2 + 1); /* also copy terminating 0 byte */

        return result;
}




/*
 * dst is a block of previously allocated memory
 * dst_len is the length of the previously allocated memory
 * dst_ptr points somewhere within that memory
 * on_top is the amount of bytes that comes on top of dst_ptr
 *
 * realloc_buffer() allocates additional memory in case dst_ptr + on_top
 * exceeds the previously allocated block of memory. New size will be
 * 2 * dst_len + on_topsize
 */

void realloc_buffer(char **dst, char **dst_ptr, size_t *dst_len, size_t on_top)
{
        la_vdebug("realloc_buffer(%u, %u)", *dst_len, on_top);

        if (*dst_ptr + on_top >= *dst + *dst_len)
        {
                *dst_len = *dst_len * 2 + on_top;
                la_debug("realloc_buffer()=%u", *dst_len);

                void *tmp_ptr;
                tmp_ptr = xrealloc(*dst, *dst_len);
                *dst_ptr = *dst_ptr - *dst + tmp_ptr;
                *dst = tmp_ptr;
        }
}


kw_list_t *
xcreate_list(void)
{
        kw_list_t *result = xmalloc(sizeof (kw_list_t));

        result->head.succ = (kw_node_t *) &result->tail;
        result->head.pred = NULL;
        result->tail.succ = NULL;
        result->tail.pred = (kw_node_t *) &result->head;

        assert_list(result);

        return result;
}


/* vim: set autowrite expandtab: */
