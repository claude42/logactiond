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

#include <pthread.h>
#include <syslog.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "logactiond.h"

pthread_t fifo_thread = 0;

static FILE *fifo;

static void
cleanup_fifo(void *arg)
{
        la_debug("cleanup_fifo()");

        if (fifo && fclose(fifo))
                la_log_errno(LOG_ERR, "Problem closing fifo");

        if (remove(FIFOFILE) == -1 && errno != ENOENT)
                la_log_errno(LOG_ERR, "Cannot remove fifo");
}

static void
create_fifo(void)
{
        la_debug("create_fifo()");

        if (mkfifo(FIFOFILE, 0666) == -1)
                die_err("Cannot create fifo");

        fifo = fopen(FIFOFILE, "r+");
        if (!fifo)
                die_err("Cannot open fifo");
}

static void
trigger_manual_command(la_address_t *address, la_command_t *template,
                unsigned int duration)
{
        assert_address(address); assert_command(template);
        la_debug("trigger_manual_command()");

        la_command_t *tmp = find_end_command(address);
        if (tmp)
        {
                la_log(LOG_INFO, "Host: %s, ignored, action \"%s\" already "
                                "active (triggered by rule \"%s\").",
                                address->text, tmp->name, tmp->rule->name);
                return;
        }

        la_command_t *command = create_manual_command_from_template(template, 
                        address);
        if (!command)
        {
                la_log(LOG_ERR, "IP address doesn't match what requirements of action!");
                return;
        }

        if (duration != 0)
                command->duration = duration;

        la_log(LOG_INFO, "Host: %s, action \"%s\" activated manually.",
                        command->address->text, command->name);

        command->rule->queue_count++;

        exec_command(command, LA_COMMANDTYPE_BEGIN);
        if (command->end_string && command->duration > 0)
                enqueue_end_command(command);
        else
                free_command(command);
}

static la_rule_t *
find_rule_for_source(la_source_t *source, char *rulename)
{
        assert_source(source); assert(rulename);
        la_debug("find_rule_for_source(%s)", rulename);

        for (la_rule_t *result = ITERATE_RULES(source->rules);
                        (result = NEXT_RULE(result));)
        {
                if (!strcmp(rulename, result->name))
                        return result;
        }

        return NULL;
}

static la_rule_t *
find_rule(char *rulename)
{
        assert(rulename); assert(la_config);
        la_debug("find_rule(%s)", rulename);

        la_rule_t *result;
#if HAVE_LIBSYSTEMD
        if (la_config->systemd_source)
        {
                result = find_rule_for_source(la_config->systemd_source,
                                rulename);
                if (result)
                        return result;
        }
#endif /* HAVE_LIBSYSTEMD */

        assert_list(la_config->sources);
        for (la_source_t *source = ITERATE_SOURCES(la_config->sources);
                        (source = NEXT_SOURCE(source));)
        {
                result = find_rule_for_source(source, rulename);
                if (result)
                        return result;
        }

        return NULL;
}

static void
add_entry(char *buffer)
{
        assert(buffer);
        la_debug("add_entry(%s)", buffer);

        char *comma = strchr(buffer, ',');
        if (!comma)
        {
                la_log(LOG_ERR, "Illegal command %s!", buffer);
                return;
        }
        *comma = '\0';
        
        char *comma2 = strchr(comma+sizeof(char), ',');
        if (comma2)
                *comma2 = '\0';

        la_address_t *address = create_address(buffer+sizeof(char));
        if (!address)
        {
                la_log(LOG_ERR, "Cannot convert address in command %s!", buffer);
                return;
        }
        if (address_on_ignore_list(address))
        {
                la_log(LOG_ERR, "Address on ignore list in command %s!", buffer);
                free_address(address);
                return;
        }
        la_debug("Found address %s", address->text);

        la_rule_t *rule = find_rule(comma+sizeof(char));
        if (!rule)
        {
                la_log(LOG_ERR, "Unable to find rule in command %s!", buffer);
                free_address(address);
                return;
        }
        la_debug("Found rule %s.", rule->name);

        unsigned int duration = 0;
        if (comma2)
        {
                char *endptr;
                duration = strtol(comma2+sizeof(char), &endptr, 10);
                if (*endptr != '\0')
                {
                        la_log(LOG_ERR, "Spurious characters in command %s!", buffer);
                        free_address(address);
                        return;
                }
        }

#if !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS)
        for (la_command_t *template = ITERATE_COMMANDS(rule->begin_commands);
                        (template = NEXT_COMMAND(template));)
                trigger_manual_command(address, template, duration);
#endif /* !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS) */

        free(address);
}

void
remove_entry(char *buffer)
{
        assert(buffer);
        la_debug("remove_entry(%s)", buffer);

        la_address_t *address = create_address(buffer+sizeof(char));
        if (!address)
        {
                la_log(LOG_ERR, "Cannot convert address in command %s!", buffer);
                return;
        }

        if (remove_and_trigger(address) == -1)
        {
                la_log(LOG_ERR, "Address %s not in end queue!", buffer);
                return;
        }

        free_address(address);
}

static void *
fifo_loop(void *ptr)
{
        la_debug("fifo_loop()");

        pthread_cleanup_push(cleanup_fifo, NULL);

        char *linebuffer = xmalloc(DEFAULT_LINEBUFFER_SIZE*sizeof(char));
        size_t linebuffer_size = DEFAULT_LINEBUFFER_SIZE*sizeof(char);

        for (;;)
        {
                if (shutdown_ongoing)
                {
                        la_debug("Shutting down fifo thread.");
                        pthread_exit(NULL);
                }

                ssize_t num_read = getline(&linebuffer, &linebuffer_size, fifo);
                if (num_read == -1)
                {
                        if (feof(fifo))
                                continue;
                        else
                                die_err("Reading from fifo failed");
                }

                if (linebuffer[num_read-1] == '\n')
                        linebuffer[num_read-1] = '\0';

                switch (*linebuffer)
                {
                        case '+':
                                add_entry(linebuffer);
                                break;
                        case '-':
                                remove_entry(linebuffer);
                                break;
                        case '0':
                                empty_end_queue();
                                break;
                        default:
                                la_log(LOG_ERR, "Unknown command: %s", linebuffer);
                                break;
                }

        }

        assert(false);
        /* Will never be reached, simply here to make potential pthread macros
         * happy */
        pthread_cleanup_pop(1);
}

/*
 * Start monitoring thread
 */

void
start_fifo_thread(void)
{
        la_debug("start_fifo_thread()");
        assert(!fifo_thread);

        create_fifo();

        xpthread_create(&fifo_thread, NULL, fifo_loop, NULL, "fifo");
}


/* vim: set autowrite expandtab: */
