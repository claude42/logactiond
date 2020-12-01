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

#include <time.h>
#include <pthread.h>
#include <assert.h>
#include <limits.h>
#include <stdatomic.h>

#include "ndebug.h"
#include "logactiond.h"
#include "addresses.h"
#include "commands.h"
#include "configfile.h"
#include "endqueue.h"
#include "logging.h"
#include "misc.h"
#include "nodelist.h"
#include "rules.h"

la_command_t *end_queue_adr = NULL;
la_command_t *end_queue_end_time = NULL;
int queue_length = 0;
pthread_t end_queue_thread = 0;
pthread_mutex_t end_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t end_queue_condition = PTHREAD_COND_INITIALIZER;

static void
recursively_update_queue_count_numbers(la_command_t *command)
{
        if (!command)
                return;
        assert_command(command);

        recursively_update_queue_count_numbers(command->adr_left);
        recursively_update_queue_count_numbers(command->adr_right);

        la_rule_t *rule = NULL;

        if (!command->is_template)
        {
                rule = find_rule(command->rule_name);
                if (rule)
                        rule->queue_count++;
        }

        /* Clean up pointers to stuff that will soon cease to
         * exist.  Just to make sure, nobdoy acidentally wants
         * to use outdated stuff it later on */
        command->rule = rule;
        command->pattern = NULL;
}

/*
 * Only invoked after a config reload. Goes through all commands in the
 * end_queue (skipping the shutdown commands) and tries to find matching new
 * rules. If found, adjusts the rule's queue counter accordingly.
 *
 * On the fly it cleans up command->rule and command->pattern of all commands
 * to avoid other code will follow wrong pointers.
 */

void
update_queue_count_numbers(void)
{
        la_debug("update_queue_count_numbers()");

        xpthread_mutex_lock(&config_mutex);
        xpthread_mutex_lock(&end_queue_mutex);

                recursively_update_queue_count_numbers(end_queue_adr);

        xpthread_mutex_unlock(&end_queue_mutex);
        xpthread_mutex_unlock(&config_mutex);
}

/*
 * Search for a command by a certain host for a given rule on the end_que
 * list. Return if found, return NULL otherwise
 *
 * host may be NULL
 */

static la_command_t *
find_end_command_no_mutex(const la_address_t *const address)
{
        la_debug("find_end_command_no_mutex()");

        if (!address)
                return NULL;
        assert_address(address);

        if (!end_queue_adr)
                return NULL;
        assert_command(end_queue_adr);
        la_command_t *result = end_queue_adr;

        while (result)
        {
                int cmp = adrcmp(result->address, address);
                if (cmp == 0)
                {
                        break;
                }
                else if (cmp < 0 && result->adr_right)
                {
                        result = result->adr_right;
                }
                else if (cmp > 0 && result->adr_left)
                {
                        result = result->adr_left;
                }
                else
                {
                        result = NULL;
                        break;
                }
        }

        return result;
}

la_command_t *
find_end_command(const la_address_t *const address)
{
        la_command_t *result = NULL;

        xpthread_mutex_lock(&end_queue_mutex);

                result = find_end_command_no_mutex(address);

        xpthread_mutex_unlock(&end_queue_mutex);

        return result;
}

static void
remove_command_from_queues(la_command_t *command)
{
        assert_command(command);
        if (command->adr_parent)
                assert_command(command->adr_parent);

        /* Used to alternatingly use left or right subtree */
        static int left_or_right = 0;

        la_command_t *parent = command->adr_parent;
        la_command_t **ptr = NULL;

        if (parent)
        {
                assert (parent->adr_left == command || parent->adr_right == command);

                if (parent->adr_left == command)
                        ptr = &parent->adr_left;
                else if (parent->adr_right == command)
                        ptr = &parent->adr_right;
        }
        else
        {
                ptr = &end_queue_adr;
        }

        if (command->adr_left == NULL)
        {
                /* if left subtree does not exist simply attach right subtree
                 * to parent and we're done */
                *ptr = command->adr_right;
        } else if (command->adr_right == NULL)
        {
                /* if right subtree does not exist simply attach left subtree
                 * to parent and we're done */
                *ptr = command->adr_left;
        }
        else
        {
                /* if both subtrees exist, then randomly attach one of the
                 * subtrees and attach the other to the its opposite far end */
                if ((left_or_right++ % 2) == 0)
                {
                        *ptr = command->adr_left;
                        la_command_t *q;
                        /* find far right end of left subtree */
                        for (q = command->adr_left; q->adr_right; q = q->adr_right)
                                ;
                        q->adr_right = command->adr_right;
                }
                else
                {
                        *ptr = command->adr_right;
                        la_command_t *q;
                        /* find far left end of right subtree */
                        for (q = command->adr_right; q->adr_left; q = q->adr_left)
                                ;
                        q->adr_left = command->adr_left;
                }
        }

        /* Clean up dangling links of removed command just to make sure they
         * won't be used anymore */
        command->adr_parent = command->adr_left = command->adr_right = NULL;

        parent = command->end_time_parent;

        if (parent)
        {
                assert (parent->end_time_left == command || parent->end_time_right == command);

                if (parent->end_time_left == command)
                        ptr = &parent->end_time_left;
                else if (parent->end_time_right == command)
                        ptr = &parent->end_time_right;
        }
        else
        {
                ptr = &end_queue_end_time;
        }

        if (command->end_time_left == NULL)
        {
                *ptr = command->end_time_right;
        } else if (command->end_time_right == NULL)
        {
                *ptr = command->end_time_left;
        }
        else
        {
                if ((left_or_right++ % 2) == 0)
                {
                        *ptr = command->end_time_left;
                        la_command_t *q;
                        for (q = command->end_time_left; q->end_time_right; q = q->end_time_right)
                                ;
                        q->end_time_right = command->end_time_right;
                }
                else
                {
                        *ptr = command->end_time_right;
                        la_command_t *q;
                        for (q = command->end_time_right; q->end_time_left; q = q->end_time_left)
                                ;
                        q->end_time_left = command->end_time_left;
                }
        }

        /* Clean up dangling links of removed command just to make sure they
         * won't be used anymore */
        command->end_time_parent = command->end_time_left = command->end_time_right = NULL;

        assert(queue_length > 0);
        queue_length--;
}


/*
 * Searches for command with given address in end queue. If found, removes it
 * from end queue, triggers it and then frees it.
 *
 * Will lock the endqueue mutex thus must not be called from functions which
 * already have locked the mutex (such as consume_end_queue()).
 */

int
remove_and_trigger(la_address_t *const address)
{
        assert_address(address);
        la_debug("remove_and_trigger()");

        int result = -1;

        xpthread_mutex_lock(&end_queue_mutex);

                la_command_t *command = find_end_command_no_mutex(address);

                if (command)
                {
                        remove_command_from_queues(command);
                        trigger_end_command(command, false);
                        free_command(command);
                        result = 0;
                }
                else
                {
                        result = -1;
                }

        xpthread_mutex_unlock(&end_queue_mutex);

        return result;
}

static void
recursively_empty_queue(la_command_t *command)
{
        if (!command)
                return;
        assert_command(command);

        recursively_empty_queue(command->adr_left);

        la_command_t *adr_right = command->adr_right;

        if (!command->quick_shutdown || command->is_template)
                trigger_end_command(command, true);
        free_command(command);

        recursively_empty_queue(adr_right);
}

#ifndef NOCOMMANDS
/*
 * Remove and trigger all remaining end and shutdown commands in the queue
 */

void
empty_end_queue(void)
{
        /* Always remember: don't call die_xxx() from in here as this will
         * call shutdown_daemon() again and we will end up in a fun loop... */
        la_log(LOG_INFO, "Flushing active actions.");

        /* Don't care about locking the mutex in case of system shutdown as
         * empty_end_queue() has been called from cleanup action.
         *
         * Of course also don't touch mutex if no thread is running. */
        if (!shutdown_ongoing && end_queue_thread)
                xpthread_mutex_lock(&end_queue_mutex);

        recursively_empty_queue(end_queue_adr);
        end_queue_adr = end_queue_end_time = NULL;
        queue_length = 0;

        if (!shutdown_ongoing && end_queue_thread)
        {
                /* signal probably not strictly necessary... */
                xpthread_cond_signal(&end_queue_condition);
                xpthread_mutex_unlock(&end_queue_mutex);
        }
}
#endif /* NOCOMMANDS */



/*
 * Will wait until the next end command has to be executed. In case the next
 * command is not an end command but a shutdown command, wait indefinitely (or
 * rather until daemon is stopped).
 *
 * Runs in end_queue_thread
 */

static void
wait_for_next_end_command(const la_command_t *command)
{
        /* Commented out assert_command() as going through this from the
         * endqueue thread would actually require locking the config_mutex. But
         * obviously that's a bit much "just for" an assert() */
        /* assert_command(command);*/
        assert(command->end_string);
        la_vdebug("wait_for_next_end_command(%s, %lu)", command->end_string,
                        command->end_time);

        if (command->end_time == INT_MAX)
        {
                /* next command is a shutdown command, wait indefinitely */
                (void) xpthread_cond_wait(&end_queue_condition, &end_queue_mutex);
        }
        else
        {
                /* next command is a end command, wait until its end_time */
                struct timespec wait_interval;
                wait_interval.tv_nsec = 0;
                wait_interval.tv_sec = command->end_time;
                xpthread_cond_timedwait(&end_queue_condition, &end_queue_mutex,
                                &wait_interval);
        }
}

/*
 * Will only be called when thread exits.
 */

static void
cleanup_end_queue(void *arg)
{
        la_debug("cleanup_end_queue()");

        empty_end_queue();
}

static la_command_t *
leftmost_command(la_command_t *const command)
{
        la_command_t *result = command;

        while (result->end_time_left)
                result = result->end_time_left;

        return result;
}

la_command_t *
first_command_in_queue(void)
{
        if (!end_queue_end_time)
                return NULL;
        else
                return leftmost_command(end_queue_end_time);
}

la_command_t *
next_command_in_queue(la_command_t *const command)
{
        if (command->end_time_right)
        {
                return leftmost_command(command->end_time_right);
        }
        else
        {
                la_command_t *result = command;
                while (result->end_time_parent &&
                                result == result->end_time_parent->end_time_right)
                        result = result->end_time_parent;
                return result;
        }
}

/*
 * Consumes next end command from end queue and triggers it (if any) then waits
 * appropriate amount of time.
 *
 * Runs in end_queue_thread
 */

static void *
consume_end_queue(void *ptr)
{
        la_debug("consume_end_queue()");

        pthread_cleanup_push(cleanup_end_queue, NULL);

        xpthread_mutex_lock(&end_queue_mutex);

                for (;;)
                {
                        if (shutdown_ongoing)
                        {
                                la_debug("Shutting down end queue thread.");
                                pthread_exit(NULL);
                        }

                        if (!end_queue_adr)
                        {
                                /* list is empty, wait indefinitely */
                                xpthread_cond_wait(&end_queue_condition,
                                                &end_queue_mutex);
                        }
                        else
                        {
                                la_command_t *const command =
                                        first_command_in_queue();

                                if (xtime(NULL) < command->end_time)
                                {
                                        /* non-empty list, but end_time of
                                         * first command not reached yet */
                                        wait_for_next_end_command(command);
                                }
                                else
                                {
                                        /* end_time of next command reached,
                                         * remove it and don't sleep but
                                         * immediately look for more */
                                        remove_command_from_queues(command);

                                        trigger_end_command(command, false);

                                        free_command(command);
                                }

                        }
                }

        assert(false);
        /* Will never be reached, simple here to make potential pthread macros
         * happy */
        pthread_cleanup_pop(1);
}

void
init_end_queue(void)
{
        la_debug("create_end_queue()");
        //assert(!end_queue);

        //end_queue = xcreate_list();
}


void
start_end_queue_thread(void)
{
        la_debug("init_queue_processing()");

        init_end_queue();

        xpthread_create(&end_queue_thread, NULL, consume_end_queue, NULL,
                        "end queue");
}



/*
 * Set end time to current time + duration. Set to INT_MAX in case duration ==
 * INT_MAX.
 */

static void
set_end_time(la_command_t *const command, const time_t manual_end_time)
{
        assert_command(command);
        assert(command->end_string);
        la_vdebug("set_end_time(%s, %u)", command->end_string, command->duration);

        if (manual_end_time)
        {
                command->end_time = manual_end_time;
        }
        else if (command->duration == INT_MAX)
        {
                command->end_time = INT_MAX;
        }
        else
        {
                if (command->factor != -1)
                        command->end_time = xtime(NULL) +
                                (long) command->duration * command->factor;
                else
                        command->end_time = xtime(NULL) + command->rule->meta_max;
        }
}

static void
recursively_add_to_end_queue_adr(la_command_t **root, la_command_t *command)
{
        assert_command(*root);

        if (adrcmp(command->address, (*root)->address) <= 0)
        {
                if ((*root)->adr_left)
                {
                        recursively_add_to_end_queue_adr(&((*root)->adr_left),
                                        command);
                }
                else
                {
                        (*root)->adr_left = command;
                        command->adr_parent = (*root);
                }
        }
        else
        {
                if ((*root)->adr_right)
                {
                        recursively_add_to_end_queue_adr(&((*root)->adr_right),
                                        command);
                }
                else
                {
                        (*root)->adr_right = command;
                        command->adr_parent = (*root);
                }
        }
}

static void
recursively_add_to_end_queue_end_time(la_command_t **root, la_command_t *command)
{
        assert_command(*root);

        if (command->end_time <= (*root)->end_time)
        {
                if ((*root)->end_time_left)
                {
                        recursively_add_to_end_queue_end_time(&((*root)->end_time_left),
                                        command);
                }
                else
                {
                        (*root)->end_time_left = command;
                        command->end_time_parent = (*root);
                }
        }
        else
        {
                if ((*root)->end_time_right)
                {
                        recursively_add_to_end_queue_end_time(&((*root)->end_time_right),
                                        command);
                }
                else
                {
                        (*root)->end_time_right = command;
                        command->end_time_parent = (*root);
                }
        }
}

/*
 * Adds command to correct position in end queue (only if duration is
 * non-negative). Sets end time.
 */

void
enqueue_end_command(la_command_t *const end_command, const time_t manual_end_time)
{
        assert_command(end_command); assert(end_command->end_string);
        la_debug("enqueue_end_command(%s, %u)", end_command->end_string,
                        end_command->duration);
        assert(end_command->end_time < xtime(NULL));

        if (shutdown_ongoing)
                return;

        if (end_command->duration <= 0)
                return;

        set_end_time(end_command, manual_end_time);

        xpthread_mutex_lock(&end_queue_mutex);

                if (end_queue_adr)
                {
                        recursively_add_to_end_queue_adr(&end_queue_adr,
                                        end_command);
                }
                else
                {
                        end_queue_adr = end_command;
                        end_command->adr_parent = NULL;
                }

                if (end_queue_end_time)
                {
                        recursively_add_to_end_queue_end_time(&end_queue_end_time,
                                        end_command);
                }
                else
                {
                        end_queue_end_time = end_command;
                        end_command->end_time_parent = NULL;
                }

                queue_length++;

                xpthread_cond_signal(&end_queue_condition);

        xpthread_mutex_unlock(&end_queue_mutex);
}

/* vim: set autowrite expandtab: */
