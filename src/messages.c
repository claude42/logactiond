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

#include <assert.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>

#include "logactiond.h"

/*
 * Message format:
 *  - First char is always the protocol version encoded as a single ASCII character
 *  - Second char is the command - encoded as a single ASCII character
 *  - Rest is command specific
 *  - Maximum message size is 180 (protocol version '0') determined by the '+'
 *    command.
 *
 * Accepted commands:
 *
 *  "0+<ip-address>/<prefix>,<rule-name>,<end-time-in-secs>,<factor>\0"
 *    add ip address
 *  "0-<ip-address>\0"
 *    remove ip address
 *  "0F\0"
 *    flush
 *  "0R\0"
 *    reload
 *  "0S\0"
 *    shutdown
 *  "0>\0"
 *    save
 *  "0L<log-level>\0"
 *    adjust log level
 *  "00\0"
 *    reset counts
 *  "0X\0"
 *  "0X<host>\0"
 *    send all banned addresses to other host (or sending host if <host> is
 *    empty) via + command
 *  "0D\0"
 *    dump current queue state
 *  "0Y<rule>\0"
 *    enable rule
 *  "0N<rule\0"
 *    disable rule
 *
 * Example structure (with maximum lengths):
 *  "0+<ip-address>/<prefix>,<rule-name>,<end-time-in-secs>,<factor>\0"
 *   || |          | |      | |         | |                | |      |
 *   || |          | |      | |         | |                | |      +-   1 byte
 *   || |          | |      | |         | |                | +--------   4 byte
 *   || |          | |      | |         | |                +----------   1 byte
 *   || |          | |      | |         | +---------------------------  20 bytes
 *   || |          | |      | |         +-----------------------------   1 byte
 *   || |          | |      | +--------------------------------------- 100 bytes
 *   || |          | |      +-----------------------------------------   1 byte
 *   || |          | +------------------------------------------------   3 bytes
 *   || |          +--------------------------------------------------   1 byte
 *   || +-------------------------------------------------------------  46 bytes
 *   |+---------------------------------------------------------------   1 byte
 *   +----------------------------------------------------------------   1 byte
 *                                                                    ==========
 *                                                                     180 bytes
 */

#ifndef CLIENTONLY

#define IS_EMPTY_LINE(message) (*message == '\0' || *message == '#' || *message == '\n')

/*
 * Parses message and will populate address, rule, end time and factor. You
 * must supply pointers to address and rule. If one of end_time or factor is
 * NULL, it will be skipped.
 *
 * In case of an empty line (or full line comment), address will point to NULL.
 *
 * In case end_time or end_time+factor are not part of the message, the values
 * will be set to 0.
 *
 * Return values
 * -  1 command successfully parsed
 * -  0 empty line or comment
 * - -1 parse error
 *
 * NB: address will be newly created and must be freed() by the caller, rule
 * will NOT be created and thus must NOT be free()ed!
 *
 * NB2: this function will modify the message buffer!
 */

int
parse_add_entry_message(const char *message, la_address_t **address, la_rule_t **rule,
                time_t *end_time, int *factor)
{
        assert(message); assert(address); assert(rule);
        la_debug("parse_add_entry_message(%s)", message);

        /* Ignore empty lines or comments */
        if (IS_EMPTY_LINE(message))
        {
                *address = NULL; *rule = NULL;
                if (end_time)
                        *end_time = 0;
                if (factor)
                        *factor = 0;
                return 0;
        }

        char parsed_address_str[MSG_ADDRESS_LENGTH + 1];
        char parsed_rule_str[MSG_RULE_LENGTH + 1];
        unsigned int parsed_end_time; unsigned int parsed_factor;
        const int n = sscanf(message, PROTOCOL_VERSION_STR "+%50[^,],%100[^,],%u,%u",
                        parsed_address_str, parsed_rule_str, &parsed_end_time,
                        &parsed_factor);

        if (n < 2)
                LOG_RETURN(-1, LOG_ERR, "Ignoring illegal command \"%s\"!", message);

        *address = create_address(parsed_address_str);
        if (!*address)
                LOG_RETURN(-1, LOG_ERR, "Cannot convert address in command %s!", message);

        *rule = find_rule(parsed_rule_str);
        if (!*rule)
        {
                free_address(*address);
                LOG_RETURN_VERBOSE(-1, LOG_ERR, "Ignoring remote message \'%s\' "
                                "- rule not active on local system", message);
        }

        if (end_time)
                *end_time = n >= 3 ? parsed_end_time : 0;

        if (factor)
                *factor = n >= 4 ? parsed_factor : 0;

        return 1;
}

/*
 * Actions
 */

static void
add_entry(const char *buffer, const char *from)
{
#if !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS)
        assert(buffer);
        la_debug("add_entry(%s)", buffer);
        la_address_t *address;
        la_rule_t *rule;
        time_t end_time;
        int factor;

        if (parse_add_entry_message(buffer, &address, &rule, &end_time,
                                &factor) == 1 && rule->enabled)
        {
                xpthread_mutex_lock(&config_mutex);

                trigger_manual_commands_for_rule(address, rule, end_time,
                                factor, from, false);

                xpthread_mutex_unlock(&config_mutex);
                free_address(address);
        }
#endif /* !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS) */
}

static void
del_entry(const char *buffer)
{
        assert(buffer);
        la_debug("del_entry(%s)", buffer);

        la_address_t *address = create_address(buffer+2);
        if (!address)
                LOG_RETURN(, LOG_ERR, "Cannot convert address in command %s!", buffer);

        xpthread_mutex_lock(&config_mutex);
        const int r = remove_and_trigger(address);
        xpthread_mutex_unlock(&config_mutex);

        if (r == -1)
                LOG_RETURN(, LOG_ERR, "Address %s not in end queue!", buffer);

        free_address(address);
}

static void
perform_flush(void)
{
        empty_end_queue();
}

static void
perform_reload(void)
{
        trigger_reload();
}

static void
perform_shutdown(void)
{
        trigger_shutdown(EXIT_SUCCESS, errno);
}

static void
perform_save(void)
{
        save_queue_state(NULL);
}

static void
update_log_level(const char *buffer)
{
        assert(buffer);
        la_debug("update_log_level(%s)", buffer);

        char *endptr;
        errno = 0;

        const int new_log_level = strtol(buffer+2, &endptr, 10);
        if (errno || *endptr != '\0' || new_log_level < 0 || new_log_level > 9)
                LOG_RETURN(, LOG_ERR, "Cannot change to log level %s!", buffer);

        la_log (LOG_INFO, "Set log level to %u", new_log_level);
        log_level = new_log_level;
}

/* iterates through end_queue, returns array of strings wiht add commands for
 * all non-template commands in end_queue
 */

// TODO

/*
static char **
create_add_messages_for_end_queue(void)
{
        xpthread_mutex_lock(&end_queue_mutex);

        int queue_length = list_length(end_queue);
        char **message_array = (char **) xmalloc((queue_length + 1) *
                        sizeof (char *));
        int message_array_length = 0;

        for (la_command_t *command = ITERATE_COMMANDS(end_queue);
                        (command = NEXT_COMMAND(command));)
        {
                if (!command->is_template && command->address)

                {
                        assert(message_array_length < queue_length);
                        message_array[message_array_length++] =
                                create_add_message(command->address->text,
                                                command->rule_name, NULL,
                                                NULL);
                }
        }

        xpthread_mutex_unlock(&end_queue_mutex);

        return message_array;
}
*/

/* 
 * start_routine for pthread_create called from sync_entries(). ptr points to a
 * string with the destination IP address.
 */

static void *
sync_all_entries(void *ptr)
{
        la_address_t *address = create_address_port((char *) ptr,
                        la_config->remote_port);

        if (!address)
        {
                la_log(LOG_ERR, "Cannot convert address in command %s!", ptr);
                free(ptr);
                return NULL;
        }

        free(ptr);

        xpthread_mutex_lock(&end_queue_mutex);

        const int queue_length = list_length(end_queue);
        char **message_array = (char **) xmalloc((queue_length + 1) *
                        sizeof (char *));
        int message_array_length = 0;

        for (la_command_t *command = ITERATE_COMMANDS(end_queue);
                        (command = NEXT_COMMAND(command));)
        {
                if (!command->is_template && command->address)

                {
                        assert(message_array_length < queue_length);
                        message_array[message_array_length++] =
                                create_add_message(command->address->text,
                                                command->rule_name, NULL,
                                                NULL);
                }
        }

        xpthread_mutex_unlock(&end_queue_mutex);

        for (int i = 0; i < message_array_length; i++)
        {
#ifdef WITH_LIBSODIUM
                if (la_config->remote_secret_changed)
                {
                        generate_send_key_and_salt(la_config->remote_secret);
                        la_config->remote_secret_changed = false;
                }
                if (!encrypt_message(message_array[i]))
                {
                        la_log(LOG_ERR, "Unable to encrypt message");
                        free(address);
                        return NULL;
                }
#endif /* WITH_LIBSODIUM */
                send_message_to_single_address(message_array[i], address);
                free(message_array[i]);
                xnanosleep(0, 200000000);
        }

        free(message_array);
        free_address(address);

        return NULL;
}

static void
sync_entries(const char *buffer, const char *from)
{
        assert(buffer);
        la_debug("sync_entries(%s)", buffer);

        char *ptr = xstrdup(buffer[2] ? buffer+2 : from);
        //char *ptr = buffer[2] ? buffer+2 : from;

        pthread_t sync_entries_thread = 0;
        xpthread_create(&sync_entries_thread, NULL, sync_all_entries, ptr,
                        "sync");

}

static void
perform_dump(void)
{
        dump_queue_status(true);
        dump_rules();
}

static void
enable_rule(const char *buffer)
{
        assert(buffer);
        la_debug("enable_rule(%s)", buffer);

        xpthread_mutex_lock(&config_mutex);

        la_rule_t *rule = find_rule(buffer+2);
        if (rule && !rule->enabled)
        {
                la_log(LOG_INFO, "Enabling rule \"%s\".", buffer+2);
                rule->enabled = true;
        }

        xpthread_mutex_unlock(&config_mutex);
}

static void
disable_rule(const char *buffer)
{
        assert(buffer);
        la_debug("disable_rule(%s)", buffer);

        xpthread_mutex_lock(&config_mutex);

        la_rule_t *rule = find_rule(buffer+2);
        if (rule && rule->enabled)
        {
                la_log(LOG_INFO, "Disabling rule \"%s\".", buffer+2);
                rule->enabled = false;
        }

        xpthread_mutex_unlock(&config_mutex);
}

void
parse_message_trigger_command(const char *buf, const char *from)
{
        la_debug("parse_message_trigger_command()");
        assert(buf);

        if (*buf != PROTOCOL_VERSION)
                LOG_RETURN(, LOG_ERR, "Wrong protocol version '%c'!");

        switch (*(buf+1))
        {
        case '+':
                add_entry(buf, from);
                break;
        case '-':
                del_entry(buf);
                break;
        case 'F':
                perform_flush();
                break;
        case 'R':
                perform_reload();
                break;
        case 'S':
                perform_shutdown();
                break;
        case '>':
                perform_save();
                break;
        case 'L':
                update_log_level(buf);
                break;
        case '0':
                reset_counts();
                break;
        case 'X':
                sync_entries(buf, from);
                break;
        case 'D':
                perform_dump();
                break;
        case 'Y':
                enable_rule(buf);
                break;
        case 'N':
                disable_rule(buf);
                break;
        default:
                la_log(LOG_ERR, "Unknown command: '%c'",
                                *(buf+1));
                break;
        }
}

#endif /* CLIENTONLY */

char *
create_add_message(const char *ip, const char *rule, const char *end_time, const char *factor)
{
	assert(ip); assert(rule);
        /* if factor is specified, end_time must be specified as well */
        assert(!factor || (factor && end_time));

        char *buffer = xmalloc(TOTAL_MSG_LEN);

        const int msg_len = snprintf(&buffer[MSG_IDX], MSG_LEN, PROTOCOL_VERSION_STR
                        "+%s,%s%s%s%s%s", ip, rule,
                        end_time ? "," : "",
                        end_time ? end_time : "",
                        factor ? "," : "",
                        factor ? factor : "");
        if (msg_len > MSG_LEN-1)
        {
                free(buffer);
                return NULL;
        }

        /* pad right here, cannot hurt even if we don't encrypt... */
        pad(buffer, msg_len+1);

        return buffer;
}

int
print_add_message(FILE *stream, const la_command_t *command)
{
	/* Don't assert_command() here to make sure this also works in case
	 * no proper configuration (la_config...) is available at the
	 * moment */
        assert(stream);

        /* TODO: would this make sense for commands w/o address as well? Then
         * maybe we should reflect this in the protocol and then implement
         * here... */
        if (!command->address)
                return 0;

        la_debug("print_add_message(%s)", command->address->text);

        return fprintf(stream, PROTOCOL_VERSION_STR "+%s,%s,%ld,%d\n",
                        command->address->text, command->rule_name,
                        command->end_time, command->factor);
}

char *
create_del_message(const char *ip)
{
	assert(ip);
        char *buffer = xmalloc(TOTAL_MSG_LEN);

        const int msg_len = snprintf(&buffer[MSG_IDX], MSG_LEN,
                        PROTOCOL_VERSION_STR "-%s", ip);
        if (msg_len > MSG_LEN-1)
                return NULL;

        /* pad right here, cannot hurt even if we don't encrypt... */
        pad(buffer, msg_len+1);

        return buffer;
}

char *
create_simple_message(const char c)
{
        char *buffer = xmalloc(TOTAL_MSG_LEN);

        buffer[MSG_IDX] = PROTOCOL_VERSION;
        buffer[MSG_IDX+1] = c;
        buffer[MSG_IDX+2] = '\0';

        /* pad right here, cannot hurt even if we don't encrypt... */
        pad(buffer, 2+1);

        return buffer;
}

char *
create_flush_message(void)
{
        return create_simple_message('F');
}

char *
create_reload_message(void)
{
        return create_simple_message('R');
}

char *
create_shutdown_message(void)
{
        return create_simple_message('S');
}

char *
create_save_message(void)
{
        return create_simple_message('>');
}

char *
create_log_level_message(const unsigned int new_log_level)
{
        assert(new_log_level <= LOG_DEBUG+2);

        char *buffer = xmalloc(TOTAL_MSG_LEN);

        const int msg_len = snprintf(&buffer[MSG_IDX], MSG_LEN, "%cL%u",
                        PROTOCOL_VERSION, new_log_level);

        /* pad right here, cannot hurt even if we don't encrypt... */
        pad(buffer, msg_len+1);

        return buffer;
}

char *
create_reset_counts_message(void)
{
        return create_simple_message('0');
}

char *
create_sync_message(const char *host)
{
        char *buffer = xmalloc(TOTAL_MSG_LEN);

        const int msg_len = snprintf(&buffer[MSG_IDX], MSG_LEN, "%cX%s",
                        PROTOCOL_VERSION, host ? host : "");

        /* pad right here, cannot hurt even if we don't encrypt... */
        pad(buffer, msg_len+1);

        return buffer;
}

char *
create_dump_message(void)
{
        return create_simple_message('D');
}

char *
create_enable_message(const char *rule)
{
        char *buffer = xmalloc(TOTAL_MSG_LEN);

        const int msg_len = snprintf(&buffer[MSG_IDX], MSG_LEN, "%cY%s",
                        PROTOCOL_VERSION, rule);

        /* pad right here, cannot hurt even if we don't encrypt... */
        pad(buffer, msg_len+1);

        return buffer;
}

char *
create_disable_message(const char *rule)
{
        char *buffer = xmalloc(TOTAL_MSG_LEN);

        const int msg_len = snprintf(&buffer[MSG_IDX], MSG_LEN, "%cN%s",
                        PROTOCOL_VERSION, rule);

        /* pad right here, cannot hurt even if we don't encrypt... */
        pad(buffer, msg_len+1);

        return buffer;
}


/* vim: set autowrite expandtab: */
