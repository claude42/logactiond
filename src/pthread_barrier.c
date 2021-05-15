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

#include <pthread.h>
#include <errno.h>

#include <config.h>

#ifndef HAVE_PTHREAD_BARRIER

#include "pthread_barrier.h"

int pthread_barrier_init(pthread_barrier_t *barrier, const pthread_barrierattr_t *attr, unsigned int count)
{
        if (count == 0)
        {
                errno = EINVAL;
                return -1;
        }

        if (pthread_mutex_init(&barrier->mutex, 0) < 0)
        {
                return -1;
        }

        if (pthread_cond_init(&barrier->cond, 0) < 0)
        {
                pthread_mutex_destroy(&barrier->mutex);
                return -1;
        }

        barrier->tripCount = count;
        barrier->count = 0;

        return 0;
}

int pthread_barrier_destroy(pthread_barrier_t *barrier)
{
        pthread_cond_destroy(&barrier->cond);
        pthread_mutex_destroy(&barrier->mutex);

        return 0;
}

int pthread_barrier_wait(pthread_barrier_t *barrier)
{
	int result = 0;
        pthread_mutex_lock(&barrier->mutex);

		barrier->count++;
		if (barrier->count >= barrier->tripCount)
		{
			barrier->count = 0;
			pthread_cond_broadcast(&barrier->cond);
			result = 1;
		}
		else
		{
			pthread_cond_wait(&barrier->cond, &barrier->mutex);
			result = 0;
		}

	pthread_mutex_unlock(&barrier->mutex);

	return result;
}

#endif /* HAVE_PTHREAD_BARRIER */
