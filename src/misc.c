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

/* define _GNU_SOURCE to get pthread_setname_np() */
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
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>



#include "logactiond.h"

#ifndef CLIENTONLY
bool created_pidfile = false;

void
remove_pidfile(void)
{
        la_debug("remove_pidfile()");

        if (created_pidfile)
        {
                if (unlink(PIDFILE) && errno != ENOENT)
                        la_log_errno(LOG_ERR, "Unable to remove pidfile");
                created_pidfile = false;
        }
}

void
create_pidfile(void)
{
#define BUF_LEN 20 /* should be enough - I think */
        la_debug("create_pidfile(" PIDFILE ")");

        int fd;
        char buf[BUF_LEN];

        fd = open(PIDFILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd == -1)
                die_err("Unable to open pidfile.");

        created_pidfile = true;

        if (ftruncate(fd, 0))
                die_err("Unable to truncate pidfile");

        snprintf(buf, BUF_LEN, "%ld\n", (long) getpid());
        if (write(fd, buf, BUF_LEN) != BUF_LEN)
                die_err("Unable to write pid to pidfile");

        if (close(fd))
                die_err("Unable to close pidfile");
}

/*
 * Create thread, die if it fails
 */

void
xpthread_create(pthread_t *thread, const pthread_attr_t *attr,
                void *(*start_routine)(void *), void *arg, const char *name)
{
        int ret = pthread_create(thread, attr, start_routine, arg);
        if (ret)
                die_val(ret, "Failed to create thread!");
#if HAVE_PTHREAD_SETNAME_NP
        if (name)
        {
                ret = pthread_setname_np(*thread, name);
                if (ret)
                        die_val(ret, "Failed to set thread name!");

        }
#elif HAVE_PTHREAD_SET_NAME_NP
        if (name)
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

int
xpthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                const struct timespec *abstime)
{
        const int ret = pthread_cond_timedwait(cond, mutex, abstime);
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

        return ret;
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
        const int ret = pthread_mutex_lock(mutex);
        if (ret)
                die_val(ret, "Failed to lock mutex!");
}

/*
 * Unlock mutex, die if pthread_mutex_lock() fails
 */

void
xpthread_mutex_unlock(pthread_mutex_t *mutex)
{
        const int ret = pthread_mutex_unlock(mutex);
        if (ret)
                die_val(ret, "Failed to unlock mutex!");
}

/* join thread, die if pthread_join() fails
 */

void
xpthread_join(pthread_t thread, void **retval)
{
        const int ret = pthread_join(thread, retval);
        if (ret)
                die_val(ret, "Faoiled to join thread!");
}

#endif /* CLIENTONLY */

time_t
xtime(time_t *tloc)
{
        const time_t result = time(tloc);
        if (result == -1)
                die_err("Can't get time!");

        return result;
}

void xfree(void *ptr)
{
        la_debug("free(%u)", ptr);
        free(ptr);
}


void *
xrealloc(void *ptr, size_t n)
{
        void *result = realloc(ptr, n);
        if (!result && n!=0)
                die_err("Memory exhausted");

        return result;
}

void *
xmalloc0(size_t n)
{
        void *result = calloc(n, 1);
        if (!result && n!=0)
                die_err("Memory exhausted");

        return result;
}

void *
xmalloc(size_t n)
{
        void *result =  malloc(n);
        if (!result && n!=0)
                die_err("Memory exhausted\n");

        return result;
}

/* strdup() clone; return NULL if s==NULL, calls die_err() in case off error */

char *
xstrdup(const char *s)
{
        if (!s)
                return NULL;

        void *result = strdup(s);
        if (!result)
                die_err("Memory exhausted\n");

        return result;
}

/* strndup() clone; return NULL if s==NULL, calls die_err() in case off error */

char *
xstrndup(const char *s, size_t n)
{
        if (!s)
                return NULL;

        void *result = strndup(s, n);
        if (!result)
                die_err("Memory exhausted\n");

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

        const size_t len1 = strlen(s1);
        const size_t len2 = strlen(s2);
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

void realloc_buffer(char **dst, char **dst_ptr, size_t *dst_len, const size_t on_top)
{
        la_vdebug("realloc_buffer(%u, %u)", *dst_len, on_top);

        if (*dst_ptr + on_top >= *dst + *dst_len)
        {
                *dst_len = *dst_len * 2 + on_top;
                la_debug("realloc_buffer()=%u", *dst_len);

                char *tmp_ptr;
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

/* Taken from https://www.gnu.org/software/libc/manual/html_node/getpass.html
 */

static ssize_t
_getpass (char **lineptr, size_t *n, FILE *stream)
{
        struct termios old, new;
        int nread;

        /* Turn echoing off and fail if we can't. */
        if (tcgetattr (fileno (stream), &old) != 0)
                return -1;
        new = old;
        new.c_lflag &= ~ECHO;
        if (tcsetattr (fileno (stream), TCSAFLUSH, &new) != 0)
                return -1;

        /* Read the password. */
        nread = getline (lineptr, n, stream);

        /* Restore terminal. */
        (void) tcsetattr (fileno (stream), TCSAFLUSH, &old);

        /* Replace trailing newline - if any */
        if (nread > 0 && (*lineptr)[nread-1] == '\n')
                (*lineptr)[nread-1] = '\0';

        return nread;
}

size_t password_size = 0;
static char *password_buffer = NULL;

char *
xgetpass(const char *prompt)
{
        printf("%s", prompt);
        FILE *tty = fopen("/dev/tty", "r");
        if (!tty)
                die_err("Can't open /dev/tty");

        (void) _getpass(&password_buffer, &password_size, tty);

        if (fclose(tty) == EOF)
                die_err("Can't close /dev/tty");

        puts("");

        return password_buffer;
}

int
xnanosleep(const time_t secs, const long nanosecs)
{
        struct timespec blink;

        blink.tv_sec = secs;
        blink.tv_nsec = nanosecs;

        return nanosleep(&blink, NULL);
}


/* vim: set autowrite expandtab: */
