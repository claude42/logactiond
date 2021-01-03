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
#include "binarytree.h"

kw_tree_t *adr_tree = NULL;
kw_tree_t *end_time_tree = NULL;

int queue_length = 0;
pthread_t end_queue_thread = 0;
pthread_mutex_t end_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t end_queue_condition = PTHREAD_COND_INITIALIZER;

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
        assert(adr_tree);

        xpthread_mutex_lock(&config_mutex);
        xpthread_mutex_lock(&end_queue_mutex);

                for (kw_tree_node_t *node = first_tree_node(adr_tree); node;
                                (node = next_node_in_tree(node)))
                {
                        la_rule_t *rule = NULL;

                        la_command_t *command = (la_command_t *) node->payload;
                        assert_command(command);
                        if (!command->is_template)
                        {
                                rule = find_rule(command->rule_name);
                                if (rule)
                                        rule->queue_count++;
                        }

                        /* Clean up pointers to stuff that will soon cease to
                         * exist.  Just to make sure, nobdoy accidentally wants
                         * to use outdated stuff it later on */
                        command->rule = rule;
                        command->pattern = NULL;
                }

        xpthread_mutex_unlock(&end_queue_mutex);
        xpthread_mutex_unlock(&config_mutex);
}

static int
cmp_command_address(const void *p1, const void *p2)
{
        return adrcmp(((la_command_t *) p1)->address, (la_address_t *) p2);
}

/*
 * Search for a command by a certain host for a given rule on the end_que
 * list. Return if found, return NULL otherwise
 *
 * address may be NULL
 */

static la_command_t *
find_end_command_no_mutex(const la_address_t *const address)
{
        la_debug("find_end_command_no_mutex()");

        if (!address)
                return NULL;
        assert_address(address);

        if (queue_length == 0)
                return NULL;

        kw_tree_node_t *node = (kw_tree_node_t *) find_tree_node(adr_tree,
                        address, cmp_command_address);
        if (node)
                return (la_command_t *) node->payload;
        else
                return NULL;
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
        assert_command(command); assert(adr_tree); assert(end_time_tree);

        remove_tree_node(adr_tree, &(command->adr_node));
        remove_tree_node(end_time_tree, &command->end_time_node);

        assert(queue_length > 0);
        queue_length--;
}

static int
cmp_addresses(const void *p1, const void *p2)
{
        return adrcmp(((la_command_t *) p1)->address, ((la_command_t *) p2)->address);
}

static int
cmp_end_times(const void *p1, const void *p2)
{
        return ((la_command_t *) p1)->end_time - ((la_command_t *) p2)->end_time;
}

static void
add_command_to_queues(la_command_t *command)
{
        assert_command(command); assert(adr_tree); assert(end_time_tree);

        add_to_tree(adr_tree, &command->adr_node, cmp_addresses);
        add_to_tree(end_time_tree, &command->end_time_node, cmp_end_times);

        queue_length++;
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

#ifndef NOCOMMANDS
static void
finalize_command(const void *p)
{
        la_command_t *command = (la_command_t *) p;
        assert_command(command);

        if (!command->quick_shutdown || command->is_template)
                trigger_end_command(command, true);
        free_command(command);
}

/*
 * Remove and trigger all remaining end and shutdown commands in the queue
 */

void
empty_end_queue(void)
{
        /* Always remember: don't call die_hard() from in here as this will
         * call shutdown_daemon() again and we will end up in a fun loop... */
        la_log(LOG_INFO, "Flushing active actions.");

        /* Don't care about locking the mutex in case of system shutdown as
         * empty_end_queue() has been called from cleanup action.
         *
         * Of course also don't touch mutex if no thread is running. */
        if (!shutdown_ongoing && end_queue_thread)
                xpthread_mutex_lock(&end_queue_mutex);

        empty_tree(adr_tree, finalize_command, false);
        /* manually reset end_time_tree, adr_tree has already been reset by
         * empty_tree() */
        end_time_tree->root = NULL;
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

        free_tree(adr_tree);
        adr_tree = NULL;

        free_tree(end_time_tree);
        end_time_tree = NULL;
}

static la_command_t *
return_payload_as_command(kw_tree_node_t *node)
{
        if (node)
                return (la_command_t *) node->payload;
        else
                return NULL;
}

la_command_t *
first_command_in_queue(void)
{
        return return_payload_as_command(first_tree_node(end_time_tree));
}

la_command_t *
next_command_in_queue(la_command_t *const command)
{
        return return_payload_as_command(next_node_in_tree(
                                &command->end_time_node));
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
                /* If command was activated due to a blacklist listing, use
                 * rule->dnsbl_duration, thus ignoring the duration parameter
                 * used when creating the command. Should not be a problem for
                 * templates, as these always created in configfile.c and never
                 * via a blacklist. */
                int duration = command->blacklist ?
                        command->rule->dnsbl_duration : command->duration;

                if (command->factor != -1)
                        command->end_time = xtime(NULL) +
                                (long) duration * command->factor;
                else
                        command->end_time = xtime(NULL) + command->rule->meta_max;
        }
}

static void
remove_or_renew(la_command_t *const command)
{
        const char *blname = NULL;
        if (command->blacklist)
                blname = command_address_on_dnsbl(command);

        if (blname)
        {
                remove_tree_node(end_time_tree, &command->end_time_node);
                set_end_time(command, 0);
                la_log_verbose(LOG_INFO, "Host: %s still on blacklist %s, action "
                                "\"%s\" renewed (%us).", command->address->text,
                                blname, command->name, command->end_time - xtime(NULL));
                command->submission_type = LA_SUBMISSION_RENEW;
                add_to_tree(end_time_tree, &command->end_time_node, cmp_end_times);
        }
        else
        {
                remove_command_from_queues(command);
                trigger_end_command(command, false);
                free_command(command);
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

                        if (queue_length == 0)
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
                                        remove_or_renew(command);
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
        assert(!adr_tree); assert(!end_time_tree);

        adr_tree = create_tree();
        end_time_tree = create_tree();
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

                add_command_to_queues(end_command);
                xpthread_cond_signal(&end_queue_condition);

        xpthread_mutex_unlock(&end_queue_mutex);
}



/* vim: set autowrite expandtab: */
