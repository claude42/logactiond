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
#include <arpa/inet.h>

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
find_end_command(la_rule_t *rule, la_address_t *address)
{
        assert_rule(rule);
        la_debug("find_end_command(%s)", rule->name);

        if (!end_queue)
                return NULL;

        if (!address)
                return NULL;

        la_command_t *result = NULL;

        xpthread_mutex_lock(&end_queue_mutex);

        for (la_command_t *command = ITERATE_COMMANDS(end_queue);
                        (command = NEXT_COMMAND(command));)
        {
                if (command->rule == rule &&
                                !adrcmp(command->address, address))
                {
                        result = command;
                        break;
                }
        }

        pthread_mutex_unlock(&end_queue_mutex);

        return result;
}

/*
 * Remove and trigger all remaining end and shutdown commands in the queue
 */

void
empty_end_queue(void)
{
        /* Always remember: don't call die_xxx() from in here as this will
         * call shutdown_daemon() again and we will end up in a fun loop... */
        la_debug("empty_end_queue()");

        if (!end_queue)
                return;

        xpthread_mutex_lock(&end_queue_mutex);

        for (la_command_t *tmp;
                        (tmp = REM_COMMANDS_HEAD(end_queue));)
        {
                trigger_end_command(tmp);
                free_command(tmp);
        }

        dump_queue_status(end_queue);

        pthread_mutex_unlock(&end_queue_mutex);
}

/*
 * Will wait until the next end command has to be executed. In case the next
 * command is not an end command but a shutdown command, wait indefinitely (or
 * rather until daemon is stopped).
 */

static void
wait_for_next_end_command(la_command_t *command)
{
        assert_command(command);
        la_vdebug("wait_for_next_end_command(%s, %u)", command->end_string,
                        command->end_time);

        if (command->end_time == INT_MAX)
        {
                /* next command is a shutdown command, wait indefinitely */
                xpthread_cond_wait(&end_queue_condition, &end_queue_mutex);
        }
        else
        {
                /* next command is a end command, wait until its end_time */
                struct timespec wait_interval;
                wait_interval.tv_nsec = 0;
                wait_interval.tv_sec = command->end_time;
                pthread_cond_timedwait(&end_queue_condition, &end_queue_mutex,
                                &wait_interval);
        }
}

/*
 * Consumes next end command from end queue and triggers it (if any) then waits
 * appropriate amount of time.
 */

static void *
consume_end_queue(void *ptr)
{
        la_debug("consume_end_queue()");

        xpthread_mutex_lock(&end_queue_mutex);

        for (;;)
        {
                time_t now = xtime(NULL);

                la_command_t *command = (la_command_t *) end_queue->head.succ;

                if (is_list_empty(end_queue))
                {
                        /* list is empty, wait indefinitely */
                        xpthread_cond_wait(&end_queue_condition, &end_queue_mutex);
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
                        remove_node((kw_node_t *) command);
                        trigger_end_command(command);
                        free_command(command);
                        dump_queue_status(end_queue);
                }
        }
}

/*
 * Initializes end que structure and then launches end queue thread.
 */

void
init_end_queue(void)
{
        la_debug("init_end_queue()");

        end_queue = create_list();

        dump_queue_status(end_queue);

        pthread_t end_queue_thread;

        if (pthread_create(&end_queue_thread, NULL, consume_end_queue, NULL))
                die_hard("Couldn't create end_queue thread!");
}

/*
 * Set end time to current time + duration. Set to INT_MAX in case duration ==
 * INT_MAX.
 */

static void
set_end_time(la_command_t *command)
{
        assert_command(command);
        la_vdebug("set_end_time(%s, %u)", command->end_string, command->duration);

        if (command->duration == INT_MAX)
                command->end_time = INT_MAX;
        else
                command->end_time = xtime(NULL) + command->duration;
}

/*
 * Adds command to correct position in end queue (only if duration is
 * non-negative). Sets end time.
 */

void
enqueue_end_command(la_command_t *end_command)
{
        assert_command(end_command);
        la_debug("enqueue_end_command(%s, %u)", end_command->end_string,
                        end_command->duration);

        if (end_command->duration <= 0)
                return;

        set_end_time(end_command);

        xpthread_mutex_lock(&end_queue_mutex);

        /* We don't use the ITERATE_COMMANDS, NEXT_COMMAND here for a
         * reason... */
        la_command_t *tmp;
        for (tmp = (la_command_t *) end_queue->head.succ;
                        tmp->node.succ;
                        tmp = (la_command_t *) tmp->node.succ)
        {
                if (end_command->end_time <= tmp->end_time)
                        break;
        }

        insert_node_before((kw_node_t *) tmp, (kw_node_t *) end_command);

        dump_queue_status(end_queue);

        pthread_cond_signal(&end_queue_condition);

        pthread_mutex_unlock(&end_queue_mutex);
}

/* vim: set autowrite expandtab: */
