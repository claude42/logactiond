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
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <termios.h>
#include <signal.h>
#include <assert.h>
#include <ctype.h>

#include "ndebug.h"
#include "logactiond.h"
#include "logging.h"
#include "misc.h"

#ifndef CLIENTONLY

void
remove_pidfile(void)
{
        la_debug("remove_pidfile()");

        if (remove(pidfile_name) == -1 && errno != ENOENT)
                la_log_errno(LOG_ERR, "Unable to remove pidfile");
}

void
create_pidfile(void)
{
        la_debug("create_pidfile(%s)", pidfile_name);

        FILE *const stream = fopen(pidfile_name, "w");
        if (!stream)
                die_err("Unable to open pidfile.");

        fprintf(stream, "%ld\n", (long) getpid());

        if (fclose(stream) == EOF)
                die_err("Unable to close pidfile");
}

/* Returns true if logactiond process is already running */

bool
check_pidfile(void)
{
#define BUF_LEN 20 /* should be enough - I think */

        la_debug("check_pidfile(%s)", pidfile_name);

        bool result = true;

        FILE *const stream = fopen(pidfile_name, "r");

        if (stream)
        {
                la_debug("opened pid");
                unsigned int pid;
                if (fscanf(stream, "%u", &pid) == 1)
                        result = !(kill(pid, 0) == -1 && errno == ESRCH);
                else
                        result = false;

                if (fclose(stream) == EOF)
                        die_err("Unable to close pidfile");
        }
        else
        {
                la_debug("did not open pid");
                if (errno == ENOENT)
                        result = false;
                else
                        die_err("Unable to open pidfile.");
        }

        return result;
}

/*
 * Create thread, die if it fails
 */

void
xpthread_create(pthread_t *const thread, const pthread_attr_t *const attr,
                void *(*start_routine)(void *), void *const arg,
                const char *const name)
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
#if HAVE_PTHREAD_GETNAME_NP
#define THREAD_NAME_LEN 16
        /*char thread_name[THREAD_NAME_LEN];
        if (pthread_getname_np(pthread_self(), thread_name, THREAD_NAME_LEN))
                snprintf(thread_name, THREAD_NAME_LEN, "unnamed");
	la_vdebug("Thread %s trying to LOCK mutex %u", thread_name, mutex);*/
#endif /* HAVE_PTHREAD_GENTAME_NP */

        const int ret = pthread_mutex_lock(mutex);
        if (ret)
                die_val(ret, "Failed to lock mutex!");

#if HAVE_PTHREAD_GETNAME_NP
	/*la_vdebug("Thread %s successfully LOCKED mutex %u", thread_name, mutex);*/
#endif /* HAVE_PTHREAD_GENTAME_NP */
}

/*
 * Unlock mutex, die if pthread_mutex_lock() fails
 */

void
xpthread_mutex_unlock(pthread_mutex_t *mutex)
{
#if HAVE_PTHREAD_GETNAME_NP
#define THREAD_NAME_LEN 16
        /*char thread_name[THREAD_NAME_LEN];
        if (pthread_getname_np(pthread_self(), thread_name, THREAD_NAME_LEN))
                snprintf(thread_name, THREAD_NAME_LEN, "unnamed");
	la_vdebug("Thread %s trying to UNLOCK mutex %u", thread_name, mutex);*/
#endif /* HAVE_PTHREAD_GENTAME_NP */

        const int ret = pthread_mutex_unlock(mutex);
        if (ret)
                die_val(ret, "Failed to unlock mutex!");

#if HAVE_PTHREAD_GETNAME_NP
	/*la_vdebug("Thread %s successfully UNLOCKED mutex %u", thread_name, mutex);*/
#endif /* HAVE_PTHREAD_GENTAME_NP */
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
        la_debug("free(%p)", ptr);
        free(ptr);
}


void *
xrealloc(void *ptr, size_t n)
{
        void *const result = realloc(ptr, n);
        if (!result && n!=0)
                die_err("Memory exhausted");

        return result;
}

void *
xmalloc0(size_t n)
{
        void *const result = calloc(n, 1);
        if (!result && n!=0)
                die_err("Memory exhausted");

        return result;
}

void *
xmalloc(size_t n)
{
        void *const result =  malloc(n);
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

        void *const result = strdup(s);
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

        void *const result = strndup(s, n);
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
        char *const result = xmalloc(len1 + len2 + 1);

        memcpy(result, s1, len1);
        memcpy(result + len1, s2, len2 + 1); /* also copy terminating 0 byte */

        return result;
}

/* Will copy string from src to dest. Either
 * - until '\0' is reached or
 * - until delim is reached or
 * - until n bytes are copied (if n>0) or
 * - until dest_size - 1 bytes are copied
 *
 * whichever occurs first. Will make sure dest will end with '\0' in either case.
 *
 * Will return number of characters copied - unless available space in dest
 * would not have been enough - then will return -1.
 *
 * n must be >= 1.
 * delim should be '\0' if no special delimiter is required.
 */

int
string_copy(char *const dest, const size_t dest_size, const char *const src,
                const size_t n, char delim)
{
        assert(dest); assert(src);

        if (dest_size < 1)
                return -1;

        const size_t copy_bytes = (!n || dest_size-1 < n) ? dest_size-1 : n;
        size_t i;

        for (i = 0; i < copy_bytes && src[i] && src[i] != delim; i++)
                dest[i] = src[i];

        dest[i] = '\0';

        /* Return number of copied bytes if
         * - copying ended when '\0' or delim was reached or
         * - length (n) was specified and is smaller than dest_size.
         *
         * Return -1 otherwise - i.e when dest_size was reached
         */
        if (src[i] == '\0' || src[i] == delim || (n != 0 && n < dest_size))
                return i;
        else
                return -1;
}

int
strendcmp(const char *const string, const char *const suffix)
{
        if (!string && !suffix)
                return 0;
        else if (!string || !suffix)
                return 1;

        const int string_len = strlen(string);
        const int suffix_len = strlen(suffix);

        if (suffix_len > string_len)
                return 1;

        return strcmp(string + string_len - suffix_len, suffix);
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
        la_vdebug("realloc_buffer(%lu, %lu)", *dst_len, on_top);
        assert (*dst); assert((size_t) (*dst_ptr - *dst) < *dst_len);

        if (*dst_ptr + on_top >= *dst + *dst_len)
        {
                *dst_len = *dst_len * 2 + on_top;
                la_debug("realloc_buffer()=%lu", *dst_len);

                char *const tmp_ptr = xrealloc(*dst, *dst_len);
                *dst_ptr = *dst_ptr - *dst + tmp_ptr;
                *dst = tmp_ptr;
        }
}

/* Taken from https://www.gnu.org/software/libc/manual/html_node/getpass.html
 */

static ssize_t
_getpass (char **lineptr, size_t *n, FILE *stream)
{
        struct termios old, new;
        ssize_t nread;

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

char *
xgetpass(const char *const prompt)
{
        printf("%s", prompt);
        FILE *tty = fopen("/dev/tty", "r");
        if (!tty)
                die_err("Can't open /dev/tty");

        size_t password_size = 0;
        static char *password_buffer = NULL;
        (void) _getpass(&password_buffer, &password_size, tty);

        if (fclose(tty) == EOF)
                die_err("Can't close /dev/tty");

        puts("");

        return password_buffer;
}

int
xnanosleep(const time_t secs, const long nanosecs)
{
        const struct timespec blink = {.tv_sec = secs, .tv_nsec = nanosecs};

        return nanosleep(&blink, NULL);
}


/* vim: set autowrite expandtab: */
