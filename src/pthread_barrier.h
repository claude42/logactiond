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

/* 
 * Based on https://stackoverflow.com/questions/3640853/performance-test-sem-t-v-s-dispatch-semaphore-t-and-pthread-once-t-v-s-dispat
 * I simply assume that this is in the public domain.
 */

#ifndef __pthread_barrier_h

#define __pthread_barrier_h

#if !defined(HAVE_PTHREAD_BARRIER_T) || !defined(HAVE_PTHREAD_BARRIER_INIT) || \
	!defined(HAVE_PTHREAD_BARRIER_WAIT) || \
	!defined(HAVE_PTHREAD_BARRIER_DESTROY)

#include <pthread.h>

typedef int pthread_barrierattr_t;
typedef struct
{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int count;
    int tripCount;
} pthread_barrier_t;

int pthread_barrier_init(pthread_barrier_t *barrier,
		const pthread_barrierattr_t *attr, unsigned int count);

int pthread_barrier_destroy(pthread_barrier_t *barrier);

int pthread_barrier_wait(pthread_barrier_t *barrier);

#endif /* !defined(HAVE_PTHREAD_BARRIER_T) || !defined(HAVE_PTHREAD_BARRIER_INIT) ||
	!defined(HAVE_PTHREAD_BARRIER_WAIT) ||
	!defined(HAVE_PTHREAD_BARRIER_DESTROY) */

#endif /* __pthread_barrier_h */
