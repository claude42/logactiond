#include <config.h>

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <sys/inotify.h>
//#include <sys/select.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include <libconfig.h>

#include "logactiond.h"

static kw_list_t *end_queue = NULL;
pthread_mutex_t end_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

void
empty_end_queue(void)
{
	if (!end_queue)
		return;

	pthread_mutex_lock(&end_queue_mutex);

	la_command_t *command = (la_command_t *) end_queue->head.succ;

	while (command->node.succ)
	{
		la_debug("empty_queue(), removing %s\n", command->string);
		la_command_t *tmp = command;
		command = (la_command_t *) command->node.succ;
		remove_node((kw_node_t *) tmp);
		trigger_command(tmp);
	}

	pthread_mutex_unlock(&end_queue_mutex);
}


static void *
consume_end_queue(void *ptr)
{
	for (;;)
	{

		pthread_mutex_lock(&end_queue_mutex);

		if (!is_list_empty(end_queue))
		{
			la_command_t *command = (la_command_t *) end_queue->head.succ;
			la_debug("consume_end_queue(), next=%s, time=%u, end_time=%u\n",
					command->string, time(NULL), command->end_time);

			/* TODO: error handling */
			time_t now = time(NULL);
			if (now == -1)
				die_hard("Can't get current time\n");
			if (now > command->end_time)
			{
				remove_node((kw_node_t *) command);
				trigger_command(command);
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
	end_queue = create_list();

	pthread_t end_queue_thread;

	if (pthread_create(&end_queue_thread, NULL, consume_end_queue, NULL))
		die_hard("Couldn't create end_queue thread\n");
}

static void
set_end_time(la_command_t *command, int duration)
{
	command->duration = duration;
	command->end_time = time(NULL);
	if (command->end_time == -1)
		die_hard("Can't get current time\n");
	command->end_time += duration;
}

void
enqueue_end_command(la_command_t *end_command, int duration)
{
	la_debug("enqueue_end_command(%s, %u\n", end_command->string, duration);
	if (duration <= 0)
		return;

	set_end_time(end_command, duration);

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
