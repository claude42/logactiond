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
#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

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
 *  "0+<ip-address>/<prefix>,<rule-name>,<end-time-in-secs>,<factor>0"
 *  "0-<ip-address>"
 *  "00"
 *  "0R"
 *  "0S"
 *  "0>"
 *
 * Example structure:
 *  "0+<ip-address>/<prefix>,<rule-name>,<end-time-in-secs>,<factor>0"
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


#ifndef CLIENTONLY

int
parse_add_entry_message(char *message, la_address_t **address, la_rule_t **rule,
                time_t *end_time, int *factor)
{
        assert(message); assert(address); assert(rule);
        la_debug("parse_add_entry_message(%s)", message);

        unsigned int msg_len = xstrlen(message);

        /* Ignore empty lines or comments */
        if (!msg_len || *message == '#' || *message =='\n')
        {
                *address = NULL; *rule = NULL;
                if (end_time)
                        *end_time = 0;
                if (*factor)
                        *factor = 0;
                return 0;
        }

        char parsed_address_str[MSG_ADDRESS_LENGTH + 1];
        char parsed_rule_str[MSG_RULE_LENGTH + 1];
        int parsed_end_time; int parsed_factor;
        int n = sscanf(message, PROTOCOL_VERSION_STR "+%50[^,],%100[^,],%u,%u",
                        parsed_address_str,
                        parsed_rule_str, &parsed_end_time, &parsed_factor);

        if (n < 2)
        {
                la_log(LOG_ERR, "Ignoring illegal command \"%s\"!", message);
                return -1;
        }

        *address = create_address(parsed_address_str);
        if (!*address)
        {
                la_log(LOG_ERR, "Cannot convert address in command %s!", message);
                return -1;
        }
        la_debug("Found address %s", (*address)->text);

        *rule = find_rule(parsed_rule_str);
        if (!*rule)
        {
                la_log_verbose(LOG_ERR, "Ignoring remote message \'%s\' "
                                "- rule not active on local system", message);
                free_address(*address);
                return -1;
        }
        la_debug("Found rule %s", (*rule)->name);

        if (end_time && n >= 3)
                *end_time = parsed_end_time;
        else
                *end_time = 0;

        if (factor && n >= 4)
                *factor = parsed_factor;
        else
                *factor = 0;

        return 1;
}

/*
 * Actions
 */

static void
add_entry(char *buffer, char *from)
{
        assert(buffer);
        la_debug("add_entry(%s)", buffer);
        la_address_t *address;
        la_rule_t *rule;
        time_t end_time;
        int factor;

        if (parse_add_entry_message(buffer, &address, &rule, &end_time,
                                &factor) == 1)
        {
#if !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS)
                xpthread_mutex_lock(&config_mutex);

                trigger_manual_commands_for_rule(address, rule, end_time,
                                factor, from, false);

                xpthread_mutex_unlock(&config_mutex);
#endif /* !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS) */
                free_address(address);
        }
}

static void
del_entry(char *buffer)
{
        assert(buffer);
        la_debug("del_entry(%s)", buffer);

        la_address_t *address = create_address(buffer+2);
        if (!address)
        {
                la_log(LOG_ERR, "Cannot convert address in command %s!", buffer);
                return;
        }

        xpthread_mutex_lock(&config_mutex);
        int r = remove_and_trigger(address);
        xpthread_mutex_unlock(&config_mutex);

        if (r == -1)
        {
                la_log(LOG_ERR, "Address %s not in end queue!", buffer);
                return;
        }

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

void
parse_message_trigger_command(char *buf, char *from)
{
        if (*buf != PROTOCOL_VERSION)
        {
                la_log(LOG_ERR, "Wrong protocol version '%c'!");
                return;
        }

        switch (*(buf+1))
        {
                case '+':
                        add_entry(buf, from);
                        break;
                case '-':
                        del_entry(buf);
                        break;
                case '0':
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
                default:
                        la_log(LOG_ERR, "Unknown command: '%c'",
                                        *(buf+1));
                        break;
        }
}

#endif /* CLIENTONLY */

char *
create_add_message(char *ip, char *rule, char *end_time, char *factor)
{
	assert(ip); assert(rule);
        /* if factor is specified, end_time must be specified as well */
        assert(!factor || (factor && end_time));

        char *buffer = xmalloc(TOTAL_MSG_LEN);

        int msg_len = snprintf(&buffer[MSG_IDX], MSG_LEN, "%c+%s,%s%s%s%s%s",
                        PROTOCOL_VERSION, ip, rule,
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
print_add_message(FILE *stream, la_command_t *command)
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

        return fprintf(stream, "%c+%s,%s,%ld,%d\n", PROTOCOL_VERSION,
                        command->address->text, command->rule_name,
                        command->end_time, command->factor);
}

char *
create_del_message(char *ip)
{
	assert(ip);
        char *buffer = xmalloc(TOTAL_MSG_LEN);

        int msg_len = snprintf(&buffer[MSG_IDX], MSG_LEN, "%c-%s",
                        PROTOCOL_VERSION, ip);
        if (msg_len > MSG_LEN-1)
                return NULL;

        /* pad right here, cannot hurt even if we don't encrypt... */
        pad(buffer, msg_len+1);

        return buffer;
}

char *
create_flush_message(void)
{
        char *buffer = xmalloc(TOTAL_MSG_LEN);

        int msg_len = snprintf(&buffer[MSG_IDX], MSG_LEN, "%c0",
                        PROTOCOL_VERSION);

        /* pad right here, cannot hurt even if we don't encrypt... */
        pad(buffer, msg_len+1);

        return buffer;
}

char *
create_reload_message(void)
{
        char *buffer = xmalloc(TOTAL_MSG_LEN);

        int msg_len = snprintf(&buffer[MSG_IDX], MSG_LEN, "%cR",
                        PROTOCOL_VERSION);

        /* pad right here, cannot hurt even if we don't encrypt... */
        pad(buffer, msg_len+1);

        return buffer;
}

char *
create_shutdown_message(void)
{
        char *buffer = xmalloc(TOTAL_MSG_LEN);

        int msg_len = snprintf(&buffer[MSG_IDX], MSG_LEN, "%cS",
                        PROTOCOL_VERSION);

        /* pad right here, cannot hurt even if we don't encrypt... */
        pad(buffer, msg_len+1);

        return buffer;
}

char *
create_save_message(void)
{
        char *buffer = xmalloc(TOTAL_MSG_LEN);

        int msg_len = snprintf(&buffer[MSG_IDX], MSG_LEN, "%c>",
                        PROTOCOL_VERSION);

        /* pad right here, cannot hurt even if we don't encrypt... */
        pad(buffer, msg_len+1);

        return buffer;
}

/* vim: set autowrite expandtab: */
