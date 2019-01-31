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

#include <libconfig.h>

#include "logactiond.h"
#include "nodelist.h"

static kw_list_t *end_queue = NULL;
pthread_mutex_t end_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Search for a command by a certain host for a given rule on the end_que
 * list. Return if found, return NULL otherwise
 */

la_command_t *
find_end_command(const char *command_string, const char *host)
{
        assert(command_string);

        la_debug("find_end_command(%s)\n", command_string);

        if (!end_queue)
                return NULL;

        la_command_t *result = NULL;

        pthread_mutex_lock(&end_queue_mutex);

        for (la_command_t *command = (la_command_t *) end_queue->head.succ;
                        command->node.succ;
                        command = (la_command_t *) command->node.succ)
        {
                if (!strcmp(command->begin_string, command_string))
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


static void *
consume_end_queue(void *ptr)
{
        la_debug("consume_end_queue()\n");

	for (;;)
	{

		pthread_mutex_lock(&end_queue_mutex);

		if (!is_list_empty(end_queue))
		{
			la_command_t *command = (la_command_t *) end_queue->head.succ;
			la_debug("consume_end_queue(), next=%s, time=%u, end_time=%u\n",
					command->end_string, time(NULL), command->end_time);

			/* TODO: error handling */
			time_t now = time(NULL);
			if (now == -1)
				die_hard("Can't get current time\n");
			if (now > command->end_time)
			{
                                remove_trigger_free_command(command);
				pthread_mutex_unlock(&end_queue_mutex);
				continue; /* don't sleep, check for more list content first */
			}
			else
			{
				pthread_mutex_unlock(&end_queue_mutex);
				sleep(1);
			}
		}
		else
		{
			pthread_mutex_unlock(&end_queue_mutex);

			/* TODO: wait for signal instead of just sleep */
			sleep(1);
			la_debug("consume_end_queue(), que_empty");
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

static void
set_end_time(la_command_t *command)
{
        assert_command(command);

        la_debug("set_end_time(%s)\n", command->end_string);

	command->end_time = time(NULL);
	if (command->end_time == -1)
		die_hard("Can't get current time\n");
	command->end_time += command->duration;
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

	pthread_mutex_lock(&end_queue_mutex);

	la_command_t *tmp;
	for (tmp = (la_command_t *) end_queue->head.succ;
			tmp->node.succ;
			tmp = (la_command_t *) tmp->node.succ)
	{
		if (end_command->end_time <= tmp->end_time)
			break;
	}

	insert_node_before((kw_node_t *) tmp, (kw_node_t *) end_command);

	pthread_mutex_unlock(&end_queue_mutex);
}

/* vim: set autowrite expandtab: */
