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


#include "logactiond.h"

/*
 * Parses message and will populate address, rule and duration. If one of
 * parameters address, rule, duration is NULL, it will be skipped.
 *
 * Accepted message formart:
 * 
 *      "+<ip-address>,<rule-name>,<duation-in-seconds>"
 *
 * Please note: this function will modify the message buffer!
 */

bool
parse_add_entry_message(char *message, la_address_t **address, la_rule_t **rule,
                int *duration)
{
        assert(message);
        la_debug("parse_add_entry_message(%s)", message);

        char *comma = strchr(message, ',');
        if (!comma)
        {
                la_log(LOG_ERR, "Illegal command %s!", message);
                return false;
        }
        *comma = '\0';
        
        char *comma2 = strchr(comma+sizeof(char), ',');
        if (comma2)
                *comma2 = '\0';


        if (address)
        {
                *address = create_address(message+sizeof(char));
                if (!*address)
                {
                        la_log(LOG_ERR, "Cannot convert address in command %s!", message);
                        return false;
                }
                if (address_on_ignore_list(*address))
                {
                        la_log(LOG_ERR, "Address on ignore list in command %s!", message);
                        free_address(*address);
                        return false;
                }
                la_debug("Found address %s", (*address)->text);
        }

        if (rule)
        {
                *rule = find_rule(comma+sizeof(char));
                if (!*rule)
                {
                        la_log(LOG_ERR, "Unable to find rule in command %s!", message);
                        free_address(*address);
                        return false;
                }
                la_debug("Found rule %s.", (*rule)->name);
        }

        if (duration)
        {
                *duration = 0;
                if (comma2)
                {
                        char *endptr;
                        *duration = strtol(comma2+sizeof(char), &endptr, 10);
                        if (*endptr != '\0')
                        {
                                la_log(LOG_ERR, "Spurious characters in command %s!", message);
                                free_address(*address);
                                return false;
                        }
                }
        }

        return true;
}

/*
 * Construct an a message. Buffer must be supplied, will not be allocated.
 *
 * Message format is
 *
 *      "+<ip-address>,<rule-name>,<duation-in-seconds>"
 *
 * or
 *
 *      "+<ip-address>,<rule-name>"
 *
 * if send_duration is false.
 */

bool
create_add_entry_message(char *buffer, size_t buf_len, la_command_t *command,
                bool send_duration)
{
        int message_len;
        if (send_duration)
                message_len = snprintf(buffer, buf_len-1, "+%s,%s,%u",
                                command->address->text, command->rule_name,
                                command->duration);
        else
                message_len = snprintf(buffer, buf_len-1, "+%s,%s",
                                command->address->text, command->rule_name);

        return (message_len <= buf_len-1);
}


/* vim: set autowrite expandtab: */
