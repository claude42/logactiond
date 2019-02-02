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

#include <time.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <assert.h>
#include <limits.h>

#include <libconfig.h>

#include "logactiond.h"
#include "nodelist.h"

static kw_list_t *end_queue = NULL;
pthread_mutex_t end_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t end_queue_condition = PTHREAD_COND_INITIALIZER;

/*
 * Search for a command by a certain host for a given rule on the end_que
 * list. Return if found, return NULL otherwise
 *
 * host may be NULL
 */

la_command_t *
find_end_command(la_rule_t *rule, const char *host)
{
        assert_rule(rule);

        la_debug("find_end_command(%s)\n", rule->name);

        if (!end_queue)
                return NULL;

        la_command_t *result = NULL;

        pthread_mutex_lock(&end_queue_mutex);

        for (la_command_t *command = (la_command_t *) end_queue->head.succ;
                        command->node.succ;
                        command = (la_command_t *) command->node.succ)
        {
                if (command->rule == rule)
                {
                        if (!command->host && !host)
                        {
                                result = command;
                                break;
                        }
                        else if (command->host && host &&
                                        !strcmp(command->host, host))
                        {
                                result = command;
                                break;
                        }
                }
        }

	pthread_mutex_unlock(&end_queue_mutex);

        return result;
}

/*
 * Remove command from end_queue, trigger end command, then free it.
 */

static void
remove_trigger_free_command(la_command_t *command)
{
        assert_command(command);

        la_debug("remove_trigger_free_command(%s)\n", command->end_string);

        remove_node((kw_node_t *) command);
        trigger_end_command(command);
        free_command(command);
}


/*
 * Remove and trigger all remaining end and shutdown commands in the queue
 */

void
empty_end_queue(void)
{
        la_debug("empty_end_queue()\n");

	if (!end_queue)
		return;

	pthread_mutex_lock(&end_queue_mutex);

	la_command_t *command = (la_command_t *) end_queue->head.succ;

	while (command->node.succ)
	{
		la_debug("empty_queue(), removing %s\n", command->end_string);
		la_command_t *tmp = command;
		command = (la_command_t *) command->node.succ;
                remove_trigger_free_command(tmp);
	}

	pthread_mutex_unlock(&end_queue_mutex);
}

static void
wait_for_next_end_command(la_command_t *command)
{
        assert_command(command);
        la_debug("wait_for_next_end_command(%s)\n", command->end_string);
        if (command->end_time == INT_MAX)
        {
                /* next command is a shutdown command, wait indefinitely */
                la_debug("consume %u INT_MAX, pthread_cond_wait()\n", time(NULL));
                pthread_cond_wait(&end_queue_condition, &end_queue_mutex);
                la_debug("consume %u INT_MAX woke up\n", time(NULL));
        }
        else
        {
                /* next command is a end command, wait until its end_time */
                struct timespec wait_interval;
                wait_interval.tv_nsec = 0;
                wait_interval.tv_sec = command->end_time;
                la_debug("consume %u pthread_cond_timedwait(%u)\n",
                                time(NULL), wait_interval.tv_sec);
                pthread_cond_timedwait(&end_queue_condition, &end_queue_mutex,
                                &wait_interval);
                la_debug("consume %u woke up\n", time(NULL));
        }
}

static void *
consume_end_queue(void *ptr)
{
        la_debug("consume_end_queue()\n");

        la_debug("consume_end_queue(), %u: pthread_mutex_lock()\n", time(NULL));
        pthread_mutex_lock(&end_queue_mutex);

        for (;;)
        {
                time_t now = time(NULL);
                if (now == -1)
                        die_hard("Can't get current time\n");

                la_command_t *command = (la_command_t *) end_queue->head.succ;

                if (is_list_empty(end_queue))
                {
                        /* list is empty, wait indefinitely */
                        la_debug("consume_end_queue(), %u EMPTY pthread_cond_wait()\n", now);
                        pthread_cond_wait(&end_queue_condition, &end_queue_mutex);
                        la_debug("consume_end_queue(), %u EMPTY woke up\n", now);
                }
                else if (now < command->end_time)
                {
                        /* non-empty list, but end_time of first command not
                         * reached yet */
                        wait_for_next_end_command(command);
                }
                else
                {
                        /* end_time of next command reached, remove it
                         * and don't sleep but immediately look for more */
                        la_debug("consume %u remove_trigger_free_command()\n", now);
                        remove_trigger_free_command(command);
                }
        }
}


void
init_end_queue(void)
{
        la_debug("init_end_queue()\n");

	end_queue = create_list();

	pthread_t end_queue_thread;

	if (pthread_create(&end_queue_thread, NULL, consume_end_queue, NULL))
		die_hard("Couldn't create end_queue thread\n");
}

/*
 * Set end time to current time + duration. Set to INT_MAX in case duration ==
 * INT_MAX.
 */

static void
set_end_time(la_command_t *command)
{
        assert_command(command);

        la_debug("set_end_time(%s)\n", command->end_string);

        if (command->duration == INT_MAX)
        {
                command->end_time = INT_MAX;
        }
        else
        {
                command->end_time = time(NULL);
                if (command->end_time == -1)
                        die_hard("Can't get current time\n");
                command->end_time += command->duration;
        }
}

void
enqueue_end_command(la_command_t *end_command)
{
        assert_command(end_command);

        la_debug("enqueue_end_command(%s, %u\n", end_command->end_string,
                        end_command->duration);

	if (end_command->duration <= 0)
		return;

	set_end_time(end_command);

        la_debug("enqueue %u pthread_mutex_lock()\n", time(NULL));
	pthread_mutex_lock(&end_queue_mutex);

	la_command_t *tmp;
	for (tmp = (la_command_t *) end_queue->head.succ;
			tmp->node.succ;
			tmp = (la_command_t *) tmp->node.succ)
	{
		if (end_command->end_time <= tmp->end_time)
			break;
	}

        la_debug("enqueue %u insert_node_before()\n", time(NULL));
	insert_node_before((kw_node_t *) tmp, (kw_node_t *) end_command);
        la_debug("enqueue %u pthread_cond_signal()\n", time(NULL));
        pthread_cond_signal(&end_queue_condition);

        la_debug("enqueue %u pthread_mutex_unlock()\n", time(NULL));
	pthread_mutex_unlock(&end_queue_mutex);
}

/* vim: set autowrite expandtab: */
