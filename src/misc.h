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

#ifndef __misc_h
#define __misc_h

#include <pthread.h>
#include <stdbool.h>

#include <config.h>

#include "ndebug.h"
#include "logactiond.h"
//#include "logging.h"
#include "nodelist.h"

#define PIDFILE RUNDIR "/logactiond.pid"

#define LOG_RETURN(retval, ...) do { la_log(__VA_ARGS__); return retval; } while (0)
#define LOG_RETURN_VERBOSE(retval, ...) do { la_log_verbose(__VA_ARGS__); return retval; } while (0)
#define LOG_RETURN_ERRNO(retval, ...) do { la_log_errno(__VA_ARGS__); return retval; } while (0)

void remove_pidfile(void);

void create_pidfile(void);

bool check_pidfile(void);

void xpthread_create(pthread_t *thread, const pthread_attr_t *attr,
                void *(*start_routine)(void *), void *arg, const char *name);

void xpthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);

int xpthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                const struct timespec *abstime);

void xpthread_cond_signal(pthread_cond_t *cond);

void xpthread_mutex_lock(pthread_mutex_t *mutex);

void xpthread_mutex_unlock(pthread_mutex_t *mutex);

void xpthread_join(pthread_t thread, void **retval);

time_t xtime(time_t *tloc);

void xfree (void *ptr);

void *xrealloc(void *ptr, size_t n);

void *xmalloc0(size_t n);

void *xmalloc(size_t n);

char *xstrdup(const char *s);

char *xstrndup(const char *s, size_t n);

size_t xstrlen(const char *s);

char *concat(const char *s1, const char *s2);

char * string_copy(char *dest, size_t dest_size, const char *src);

void realloc_buffer(char **dst, char **dst_ptr, size_t *dst_len, const size_t on_top);

kw_list_t *xcreate_list(void);

char *xgetpass (const char *prompt);

int xnanosleep(time_t secs, long nanosecs);

#endif /* __misc_h */

/* vim: set autowrite expandtab: */