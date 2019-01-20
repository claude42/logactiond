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

//#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <sys/select.h>
#include <time.h>
#include <syslog.h>

#include <libconfig.h>

#include "logactiond.h"

static void
exec_command(const char *command_string)
{
	la_debug("exec_command(%s)\n", command_string);

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
get_value_for_action_property(la_property_t *action_property,
		la_pattern_t *pattern, la_rule_t *rule)
{

	la_property_t *property;
	const char *result;

	if (rule)
	{
		if (!strcmp(action_property->name, "RULE-NAME"))
			return rule->name;

		if (!strcmp(action_property->name, "SOURCE-NAME"))
			return rule->source->name;
	}

	if (pattern)
	{
		/* TODO: pattern names are not yet stored */
		/*if (!strcmp(action_property->name, "PATTERN-NAME"))
			return pattern->name;*/

		result = get_value_from_property_list(pattern->properties,
				action_property);
		if (result)
		{
			la_debug("Value=%s\n", result);
			return result;
		}
	}

	if (rule)
	{
		result = get_value_from_property_list(rule->properties,
				action_property);
		if (result)
			return result;
	}

	result = get_value_from_property_list(la_config->default_properties,
			action_property);
	if (result)
		return result;

	return NULL; /* token not present anywhere */
}

/* TODO: refactor */

static char *
convert_command(la_command_t *command)
{
	size_t len = strlen(command->string);
	/* FIXME */
	char *result = (char *) xmalloc(10000);
	char *result_ptr = result;
	const char *string_ptr = command->string;

	unsigned int start_pos = 0; /* position after last token */
	la_property_t *action_property = (la_property_t *)
		command->properties->head.succ;

	while (action_property->node.succ)
	{
		/* copy string before next token */
		result_ptr = stpncpy(result_ptr, string_ptr, action_property->pos - start_pos);

		/* copy value for token */
		const char *repl = get_value_for_action_property(
				action_property,
				command->pattern, command->rule);
		if (repl)
			result_ptr = stpncpy(result_ptr, repl, strlen(repl));
		else
			/* in case there's no value found, we now copy nothing
                         * - still TBD whether this is a good idea */
                        ;


		start_pos = action_property->pos + action_property->length;
		string_ptr = command->string + start_pos;

		action_property = (la_property_t *) action_property->node.succ;
	}

	/* Copy remainder of string - only if there's something left.
	 * Double-check just to bes sure we don't overrun any buffer */
	if (string_ptr - command->string < strlen(command->string))
		/* strcpy() ok here because we definitley reserved enough space
		 */
		strcpy(result_ptr, string_ptr);
	else
		*result_ptr = '\0';

	la_debug("convert_command(%s)=%s\n", command->string, result);
	return result;
}

void
trigger_command(la_command_t *command)
{
	char *command_string;
	la_log(LOG_DEBUG, "trigger_command(%s, %d)\n", command->string,
			command->duration);

	/* TODO: can't we convert_command() earlier? */
	command_string = convert_command(command);
	exec_command(command_string);

	if (command->end_command && command->duration > 0)
		enqueue_end_command(command->end_command, command->duration);

	//xfree(command);
}

/*
 * Returns length of token - i.e. number of characters until closing '>' is
 * found. In case string ends before closing '>', die with an error message.
 *
 * Length will include '<' and '>'
 */

static size_t
token_length(const char *string)
{
	const char *ptr = string;

	while (*ptr)
	{
		if (*ptr == '>')
			return ptr-string+1;
		ptr++;
	}

	die_semantic("Closing '>' of token missing\n");

	return 0; // avoid warning
}


/*
 * Scans pattern string for tokens. Adds found tokens to token_list.
 *
 * Return number of found tokens.
 */

static size_t
scan_single_action_token(kw_list_t *property_list, const char *string, unsigned
		int pos)
{
	size_t length = token_length(string);

	if (length > 2) /* so it's NOT just "<>" */
	{
		add_tail(property_list, (kw_node_t *)
				create_property_from_action_token(string,
					length, pos));
	}

	return length;
}


static unsigned int
scan_action_tokens(kw_list_t *property_list, const char *string)
{
	const char *ptr = string;
	unsigned int n_tokens = 0;

	if (!property_list || !string)
		die_hard("No property list or no string submitted");

	while (*ptr)
        {
		if (*ptr == '\\')
		{
			ptr++;
		}
		else if (*ptr == '<')
		{
			n_tokens++;
			ptr += scan_single_action_token(property_list, ptr,
					ptr-string);
		}
		ptr++; /* also skips over second '\\' or '>' */
	}

	return n_tokens;
}


/*
 * Clones command except for command.node. Must be freed after use. Shallow
 * copy only - except for end_command which is dup_command()ed as well.
 */

la_command_t *
dup_command(la_command_t *command)
{
	la_command_t *result = (la_command_t *) xmalloc(sizeof(la_command_t));

	result->string = command->string;
	result->properties = command->properties;
	result->n_properties = command->n_properties;
	result->rule = command->rule;
	result->pattern = command->pattern;
	result->host = command->host;
	result->end_command = command->end_command ?
		dup_command(command->end_command) : NULL;
	result->duration = command->duration;
	result->end_time = command->end_time;
	result->n_triggers = command->n_triggers;
	result->start_time = command->start_time;
	result->fire_time = command->fire_time;

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
        result->host = get_host_property_value(pattern->properties);
        if (result->end_command)
        {
                result->end_command->rule = result->rule;
                result->end_command->pattern = result->pattern;
                result->end_command->host = result->host;
        }

        return result;
}

/*
 * Creates a new command
 *
 * Duration = -1 prevents any end command
 * Duration = INT_MAX will result that the end command will only be fired on shutdown
 * FIXME: use another value than INT_MAX
 * TODO: clarify meaning of begin_command struct members vs. end_command (same?
 * end_command always ignored?
 */

la_command_t *
create_command(const char *string, int duration)
{
	la_debug("create_command(%s, %d)\n", string, duration);
	la_command_t *result = (la_command_t *) xmalloc(sizeof(la_command_t));

	result->string = string;
	result->properties = create_list();
	if (string)
		result->n_properties = scan_action_tokens(result->properties,
				string);
	else
		result->n_properties = 0;

	result->rule = NULL;
	result->pattern = NULL;
	result->host = NULL;
	result->end_command = NULL;

	result->duration = duration;
	result->end_time = 0;

	result->n_triggers = 0;
	result->start_time = 0;
	result->fire_time = 0;

	return result;
}



/* vim: set autowrite expandtab: */
