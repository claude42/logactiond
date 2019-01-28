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

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <assert.h>

#include <libconfig.h>

#include "logactiond.h"

static void
exec_command(const char *command_string)
{
	la_log(LOG_DEBUG, "exec_command(%s)\n", command_string);

	int result = system(command_string);
	if (result == -1)
		la_log(LOG_ERR, "Could not create child process for command \"%s\"", 
				command_string);
	else if (result == 127)
		la_log(LOG_ERR, "Could not execute shell for \"%s\"",
				command_string);
}

/* TODO, refactor */
/*static char*
check_for_special_names(la_property_t *action_property)
{
}*/

static const char *
get_value_for_action_property(la_command_t *command,
                la_property_t *action_property)
{
        assert(command); assert(action_property);

	la_property_t *property;
	const char *result;

        /* try some standard names first */

	if (command->rule)
	{
		if (!strcmp(action_property->name, "RULE-NAME"))
			return command->rule->name;

		if (!strcmp(action_property->name, "SOURCE-NAME"))
			return command->rule->source->name;
	}

	/* TODO: pattern names are not yet stored
        if (command->pattern)
	{
		if (!strcmp(action_property->name, "PATTERN-NAME"))
			return command->pattern->name;
        }*/

        /* next search among tokens from matched line */

        result = get_value_from_property_list(
                        command->pattern_properties,
                        action_property);
        if (result)
        {
                la_debug("Value=%s\n", result);
                return result;
        }

        /* next search in config file rule section */

	if (command->rule)
	{
		result = get_value_from_property_list(command->rule->properties,
				action_property);
		if (result)
			return result;
	}

        /* lastly search in config file default section, return NULL if
         * nothing is there either */

        return get_value_from_property_list(la_config->default_properties,
                        action_property);

}

/* TODO: refactor */

static char *
convert_command(la_command_t *command, la_commandtype_t type)
{
        const char *source_string = (type == LA_COMMANDTYPE_BEGIN) ?
                command->begin_string : command->end_string;
	size_t len = strlen(source_string);
	/* FIXME */
	char *result = (char *) xmalloc(10000);
	char *result_ptr = result;
	const char *string_ptr = source_string;

	unsigned int start_pos = 0; /* position after last token */
	la_property_t *action_property;

        if (type == LA_COMMANDTYPE_BEGIN)
                action_property = (la_property_t *) command->begin_properties->head.succ;
        else
                action_property = (la_property_t *) command->end_properties->head.succ;


	while (action_property->node.succ)
	{
		/* copy string before next token */
		result_ptr = stpncpy(result_ptr, string_ptr, action_property->pos - start_pos);

		/* copy value for token */
		const char *repl = get_value_for_action_property(command,
                                action_property);
		if (repl)
			result_ptr = stpncpy(result_ptr, repl, strlen(repl));
		else
			/* in case there's no value found, we now copy nothing
                         * - still TBD whether this is a good idea */
                        ;


		start_pos = action_property->pos + action_property->length;
		string_ptr = source_string + start_pos;

		action_property = (la_property_t *) action_property->node.succ;
	}

	/* Copy remainder of string - only if there's something left.
	 * Double-check just to bes sure we don't overrun any buffer */
	if (string_ptr - source_string < strlen(source_string))
		/* strcpy() ok here because we definitley reserved enough space
		 */
		strcpy(result_ptr, string_ptr);
	else
		*result_ptr = '\0';

	la_debug("convert_command(%s)=%s\n", command->begin_string, result);
	return result;
}

void
trigger_command(la_command_t *command)
{
	la_log(LOG_DEBUG, "trigger_command(%s, %d)\n", command->begin_string,
			command->duration);

	/* TODO: can't we convert_command() earlier? */
        exec_command(convert_command(command, LA_COMMANDTYPE_BEGIN));

        if (command->end_string && command->duration > 0)
		enqueue_end_command(command);
        else
                free_command(command);
}

void
trigger_end_command(la_command_t *command)
{
        exec_command(convert_command(command, LA_COMMANDTYPE_END));
}

/*
 * Scans pattern string for tokens. Adds found tokens to token_list.
 *
 * Return number of found tokens.
 */


static unsigned int
scan_action_tokens(kw_list_t *property_list, const char *string)
{
	const char *ptr = string;
	unsigned int n_tokens = 0;

	if (!property_list || !string)
		die_hard("No property list or no string submitted");

	while (*ptr)
        {
                if (*ptr == '%')
                {
                        size_t length = scan_single_token(property_list, ptr,
                                        ptr-string, 0);
                        if (length > 2)
                                n_tokens++;

                        ptr += length-1;
                }

		ptr++; /* also skips over second '%' */
	}

	return n_tokens;
}


/*
 * Clones command from a command template.
 * - Clones begin_string / end_string.
 * - Duplicates begin_properties / end_properties lists
 * - Does not clone host
 * Must be free()d after use.
 */

/* FIXME: when are we call dup_command()? e.g. does the property list have
 * content ever? */

la_command_t *
dup_command(la_command_t *command)
{
	la_command_t *result = (la_command_t *) xmalloc(sizeof(la_command_t));

        result->begin_string = xstrdup(command->begin_string);
	result->begin_properties = dup_property_list(command->begin_properties);
	result->n_begin_properties = command->n_begin_properties;

        result->end_string = xstrdup(command->end_string);
	result->end_properties = dup_property_list(command->end_properties);
	result->n_end_properties = command->n_end_properties;

	result->rule = command->rule;
	result->pattern = command->pattern;
        result->host = xstrdup(command->host);
	result->duration = command->duration;
	result->end_time = command->end_time;
	result->n_triggers = command->n_triggers;
	result->start_time = command->start_time;

	return result;
}


/*
 * Create command from template. Duplicate template and add add'l information
 */

la_command_t *
create_command_from_template(la_command_t *template, la_rule_t *rule,
                la_pattern_t *pattern)
{
        la_command_t *result;

        result = dup_command(template);
        result->rule = rule;
        result->pattern = pattern;
        result->pattern_properties = dup_property_list(pattern->properties);
        if (result->host)
                free(result->host);
        const char *host_property =
                get_host_property_value(pattern->properties);
        result->host = xstrdup(host_property);

        return result;
}

/*
 * Creates a new command template
 *
 * Duration = -1 prevents any end command
 * Duration = INT_MAX will result that the end command will only be fired on shutdown
 *
 * Note: begin_properties, end_properties will be initialized with
 * create_list(); pattern_properties will always be NULL after
 * create_template()
 *
 * FIXME: use another value than INT_MAX
 */

la_command_t *
create_template(la_rule_t *rule, const char *begin_string,
                const char *end_string, int duration)
{
        assert(begin_string);

	la_debug("create_command(%s, %d)\n", begin_string, duration);
	la_command_t *result = (la_command_t *) xmalloc(sizeof(la_command_t));

        result->begin_string = xstrdup(begin_string);
	result->begin_properties = create_list();
        result->n_begin_properties = begin_string ?
                scan_action_tokens(result->begin_properties, begin_string) : 0;

        result->end_string = xstrdup(end_string);
        result->end_properties = create_list();
        result->n_end_properties = end_string ?
                scan_action_tokens(result->end_properties, end_string) : 0;

	result->rule = rule;
	result->pattern = NULL;
        result->pattern_properties = NULL;
	result->host = NULL;

	result->duration = duration;
	result->end_time = 0;

	result->n_triggers = 0;
	result->start_time = 0;

	return result;
}

void
free_command(la_command_t *command)
{
        assert(command);

        free(command->begin_string);
        free_property_list(command->begin_properties);
        free(command->end_string);
        free_property_list(command->end_properties);
        free_property_list(command->pattern_properties);
        free(command->host);
}




/* vim: set autowrite expandtab: */
