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
#ifndef CLIENTONLY
#include <pthread.h>
#endif /* CLIENTONLY */
#include <limits.h>
#include <stdatomic.h>
#include <stdnoreturn.h>
#include <stdlib.h>

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
kw_list_t *end_time_list = NULL;
kw_list_t *queue_pointers = NULL;

int queue_length = 0;
#ifndef CLIENTONLY
pthread_t end_queue_thread = 0;
pthread_mutex_t end_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t end_queue_condition = PTHREAD_COND_INITIALIZER;
#endif /* CLIENTONLY */

/*
 * Only invoked after a config reload. Goes through all commands in the
 * end_queue (skipping the shutdown commands) and tries to find matching new
 * rules. If found, adjusts the rule's queue counter accordingly.
 *
 * On the fly it cleans up command->rule and command->pattern of all commands
 * to avoid other code will follow wrong pointers.
 */

#ifndef CLIENTONLY
void
update_queue_count_numbers(void)
{
        la_debug_func(NULL);
        assert_tree(adr_tree);

#ifndef CLIENTONLY
        xpthread_mutex_lock(&config_mutex);
        xpthread_mutex_lock(&end_queue_mutex);
#endif /* CLIENTONLY */

                for (kw_tree_node_t *node = adr_tree->first; node;
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
                         * to use outdated stuff later on */
                        command->rule = rule;
                        command->pattern = NULL;
                }

#ifndef CLIENTONLY
        xpthread_mutex_unlock(&end_queue_mutex);
        xpthread_mutex_unlock(&config_mutex);
#endif /* CLIENTONLY */
}
#endif /* CLIENTONLY */

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
        la_debug_func(NULL);

        if (!address)
                return NULL;
        assert_address(address);

        if (queue_length == 0)
                return NULL;

        kw_tree_node_t *node = find_tree_node(adr_tree,
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

#ifndef CLIENTONLY
        xpthread_mutex_lock(&end_queue_mutex);
#endif /* CLIENTONLY */

                result = find_end_command_no_mutex(address);

#ifndef CLIENTONLY
        xpthread_mutex_unlock(&end_queue_mutex);
#endif /* CLIENTONLY */

        return result;
}

#ifndef CLIENTONLY
static void
fix_queue_pointers(const la_command_t *const command)
{
        assert_command(command);
        la_vdebug_func(command->address ? command->address->text : NULL);

        assert_list(queue_pointers);
        if (is_list_empty(queue_pointers))
                return;

        FOREACH(la_queue_pointer_t, i, queue_pointers)
        {
                /* If we're about to remove the command the pointer is
                 * currently referring to, try its predecessor. If command has
                 * already been the first of the list, assign NULL */
                if (i->command == command)
                {
                        if (command->node.pred->pred)
                                i->command = (la_command_t *) command->node.pred;
                        else
                                i->command = NULL;
                }
        }
}
#endif /* CLIENTONLY */

static void
remove_command_from_queues(la_command_t *const command)
{
        assert_command(command); assert_tree(adr_tree); assert_list(end_time_list);
        la_debug_func(command->address ? command->address->text : NULL);

        (void) remove_tree_node(adr_tree, &(command->adr_node));
#ifndef CLIENTONLY
        fix_queue_pointers(command);
#endif /* CLIENTONLY */
        (void) remove_node((kw_node_t *) command);

        assert(queue_length > 0);
        queue_length--;
}

#ifndef CLIENTONLY
void empty_queue_pointers(void)
{
        if (!queue_pointers)
                return;

        assert_list(queue_pointers);

        xpthread_mutex_lock(&end_queue_mutex);

                empty_list(queue_pointers, NULL);

        xpthread_mutex_unlock(&end_queue_mutex);
}

static la_queue_pointer_t *
create_queue_pointer(const int duration)
{
        la_vdebug_func(NULL);
        la_queue_pointer_t *result = create_node(sizeof *result, 0, NULL);
        result->duration = duration;
        result->command = NULL;
        add_tail(queue_pointers, (kw_node_t *) result);

        return result;
}

static la_queue_pointer_t *
find_queue_pointer_for_duration_or_create_new(const int duration)
{
        la_vdebug_func(NULL);
        la_queue_pointer_t *qp = NULL;
        FOREACH_REUSE_VAR(la_queue_pointer_t, qp, queue_pointers)
        {
                if (qp->duration == duration)
                        break;
        }

        if (is_list_node(qp))
                reprioritize_node((kw_node_t *) qp, 1);
        else
                qp = create_queue_pointer(duration);

        return qp;
}
#endif /* CLIENTONLY */

static time_t
compute_duration(const la_command_t *const command)
{
        la_vdebug_func(NULL);

        assert_command(command);

        /* Factor of -1 means we're maxed out already - return maximum duation
         * we're willing to go */
        if (command->factor == -1)
                return command->rule->meta_max;

        time_t duration = 0;

        /* If command was activated due to a blacklist listing, use
         * rule->dnsbl_duration, thus ignoring the duration parameter used when
         * creating the command. Should not be a problem for templates, as
         * these always created in configfile.c and never via a blacklist. */
        if (command->previously_on_blacklist)
                duration = command->rule->dnsbl_duration;
        else
                duration = command->duration;

        return (time_t) duration * command->factor;
}

static bool
add_to_end_time_list(la_command_t *command)
{
        assert_command(command);
        la_vdebug_func(command->address ? command->address->text : NULL);

        /* first let's see if there's an existing queue pointer for this
         * duration, if not create one that points to the beginning o fthe
         * queue */
        la_command_t *tmp = NULL;
#ifndef CLIENTONLY
        la_queue_pointer_t *qp = NULL;
        /* Don't even care about queue pointer as long queue thread is not yet
         * running. This way we avoid adding lots of queue pointers while
         * restoring logactiond.state */
        if (end_queue_thread)
        {
                qp = find_queue_pointer_for_duration_or_create_new(
                                compute_duration(command));

                /* starting with the queue pointer find position where to
                 * insert the new command */
                tmp = qp->command;
        }
#endif /* CLIENTONLY */
        /* If no queue pointer found, search through the whole queue... */
        if (!tmp)
                tmp = (la_command_t *) get_head(end_time_list);

        /* In case tmp != NULL, search through list, in case tmp == NULL, list
         * is empty and simply add command */
        if (tmp)
        {
                int i = 0;
                for (; IS_NODE(tmp); GET_NEXT(la_command_t, tmp), i++)
                {
                        if (tmp->end_time > command->end_time)
                                break;
                }

                insert_node_before((kw_node_t *) tmp, (kw_node_t *) command);

#ifndef CLIENTONLY
                /* Don't let restoring logactiond.state ruin our statistics...
                 */
                if (end_queue_thread)
                        la_config->total_et_cmps += i;
#endif /* CLIENTONLY */
        }
        else
        {
                add_head(end_time_list, (kw_node_t *) command);
        }

#ifndef CLIENTONLY
        /* set queue pointer so that next search will start at inserted command
         */
        if (qp)
                qp->command = command;

        /* Again, don't let restoring logactiond.state ruin our statistics...
         */
        if (end_queue_thread)
                la_config->total_et_invs++;
#endif /* CLIENTONLY */

        /* Only return true in case command has been inserted at the start of
         * the list */
        return command == (la_command_t *) get_head(end_time_list);
}

static int
cmp_addresses(const void *p1, const void *p2)
{
        return adrcmp(((la_command_t *) p1)->address, ((la_command_t *) p2)->address);
}

/*
 * Will return true if inserted command is the will be the first in the queue -
 * i.e. the one with the nearest end_time.
 */

static bool
add_command_to_queues(la_command_t *command)
{
        assert_command(command); assert_tree(adr_tree); assert_list(end_time_list);
        la_vdebug_func(command->address ? command->address->text : NULL);

        queue_length++;

        add_to_tree(adr_tree, &command->adr_node, cmp_addresses);

        return add_to_end_time_list(command);
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
        la_debug_func(NULL);

        int result = -1;

#ifndef CLIENTONLY
        xpthread_mutex_lock(&end_queue_mutex);
#endif /* CLIENTONLY */

                la_command_t *command = find_end_command_no_mutex(address);

                if (command)
                {
                        remove_command_from_queues(command);
#ifndef NOCOMMANDS
                        trigger_end_command(command, false);
#endif /* NOCOMMANDS */
                        free_command(command);
                        result = 0;
                }
                else
                {
                        result = -1;
                }

#ifndef CLIENTONLY
        xpthread_mutex_unlock(&end_queue_mutex);
#endif /* CLIENTONLY */

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
#ifndef CLIENTONLY
        if (!shutdown_ongoing && end_queue_thread)
                xpthread_mutex_lock(&end_queue_mutex);
#endif /* CLIENTONLY */

        empty_tree(adr_tree, finalize_command, false);
        /* manually reset end_time_list, adr_tree has already been reset by
         * empty_tree() */
        init_list(end_time_list);
        queue_length = 0;

#ifndef CLIENTONLY
        if (!shutdown_ongoing && end_queue_thread)
        {
                /* signal probably not strictly necessary... */
                (void) xpthread_cond_signal(&end_queue_condition);
                xpthread_mutex_unlock(&end_queue_mutex);
        }
#endif /* CLIENTONLY */
}
#endif /* NOCOMMANDS */



/*
 * Will wait until the next end command has to be executed. In case the next
 * command is not an end command but a shutdown command, wait indefinitely (or
 * rather until daemon is stopped).
 *
 * Runs in end_queue_thread
 */

#ifndef CLIENTONLY
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
                /* Wait only once, return even if xpthread_cond_timedwait()
                 * returned with EINTR. Idea is to check for changes in the
                 * queue / to shutdown_ongoing anyway - just to be sure... */
                (void) xpthread_cond_timedwait(&end_queue_condition,
                                &end_queue_mutex, &wait_interval);
        }
}
#endif /* CLIENTONLY */

/*
 * Will only be called when thread exits.
 */

#ifndef CLIENTONLY
static void
cleanup_end_queue(void *arg)
{
        la_debug_func(NULL);

        empty_end_queue();

        free(adr_tree);
        adr_tree = NULL;

        free(end_time_list);
        end_time_list = NULL;

        free_list(queue_pointers, NULL);
        queue_pointers = NULL;

        end_queue_thread = 0;
        wait_final_barrier();
        la_debug("end queue thread exiting");
}
#endif /* CLIENTONLY */

la_command_t *
first_command_in_queue(void)
{
        return (la_command_t *) get_head(end_time_list);
}

la_command_t *
next_command_in_queue(la_command_t *const command)
{
        return command->node.succ->succ ? (la_command_t *) command->node.succ :
                NULL;
}

kw_tree_node_t *
get_root_of_queue(void)
{
        assert(adr_tree);
        return adr_tree->root;
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
                command->end_time = manual_end_time;
        else if (command->duration == INT_MAX)
                command->end_time = INT_MAX;
        else
                command->end_time = xtime(NULL) + compute_duration(command);
}

#ifndef CLIENTONLY
static void
remove_or_renew(la_command_t *const command)
{
        la_debug_func(NULL);
        const char *blname = NULL;
        if (command->previously_on_blacklist)
                blname = command_address_on_dnsbl(command);

        if (blname)
        {
                (void) remove_node(&(command->node));
                set_end_time(command, 0);
                la_log_verbose(LOG_INFO, "Host: %s still on blacklist %s, action "
                                "\"%s\" renewed (%us).", command->address->text,
                                blname, command->node.nodename,
                                command->end_time - xtime(NULL));
                command->submission_type = LA_SUBMISSION_RENEW;
                (void) add_to_end_time_list(command);
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

noreturn static void *
consume_end_queue(void *ptr)
{
        la_debug_func(NULL);

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
                                (void) xpthread_cond_wait(&end_queue_condition,
                                                &end_queue_mutex);
                        }
                        else
                        {
                                la_command_t *const command =
                                        first_command_in_queue();
                                if (!command)
                                {
                                        continue;
                                }
                                /* Subtract 1 from end_time to work around
                                 * obscure bug where pthread_cond_timedwait()
                                 * returns one second early.  See also
                                 * https://stackoverflow.com/questions/11769687/pthread-cond-timedwait-returns-one-second-early
                                 * (although this might a different issue...).
                                 */
                                else if (xtime(NULL) < command->end_time - 1)
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
#endif /* CLIENTONLY */

void
init_end_queue(void)
{
        la_debug_func(NULL);
        if (adr_tree)
                return;

        /* Just to make sure that not accidentaly only one has been initialized
         * previously */
        assert(!adr_tree); assert(!end_time_list);

        adr_tree = create_tree();
        end_time_list = create_list();
        queue_pointers = create_list();
}


#ifndef CLIENTONLY
void
start_end_queue_thread(void)
{
        la_debug_func(NULL);

        init_end_queue();

        xpthread_create(&end_queue_thread, NULL, consume_end_queue, NULL,
                        "end queue");
        thread_started();
        la_debug("End queue thread startet (%i)", end_queue_thread);
}
#endif /* CLIENTONLY */



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

#ifndef CLIENTONLY
        xpthread_mutex_lock(&end_queue_mutex);
#endif /* CLIENTONLY */

                /* wake up end queue thread only if command is the first
                 * command to execute in the list */
                if (add_command_to_queues(end_command))
                {
#ifndef CLIENTONLY
                        la_vdebug("Waking up end queue thread.");
                        xpthread_cond_signal(&end_queue_condition);
#endif /* CLIENTONLY */
                }

#ifndef CLIENTONLY
        xpthread_mutex_unlock(&end_queue_mutex);
#endif /* CLIENTONLY */
}

int
get_queue_length(void)
{
        return queue_length;
}



/* vim: set autowrite expandtab: */
