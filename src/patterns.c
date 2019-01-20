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

#include <regex.h>
//#include <stdio.h>
//#include <stdlib.h>
#include <string.h>
//#include <sys/select.h>
#include <syslog.h>

#include <libconfig.h>

#include "logactiond.h"
#include "nodelist.h"



/*
 * Replace first occurance of "<HOST>" in string by "([.:[:xdigit:]]+)"
 *
 * Returns new string, doesn't modify original.
 */

static char *
convert_regex(const char *string, kw_list_t *property_list, unsigned int n_properties)
{
	size_t len = strlen(string);
	/* definitely an upper bound */
	char *result = (char *) xmalloc(len +
			n_properties * LA_HOST_TOKEN_REPL_LEN + 1);
	char *result_ptr = result;
	const char *string_ptr = string;

	unsigned int start_pos = 0; /* position after last token */
	la_property_t *property = (la_property_t *) property_list->head.succ;

	while (property->node.succ)
	{
		/* copy string before next token */
		result_ptr = stpncpy(result_ptr, string_ptr, property->pos - start_pos);
		/* copy corresponding regular expression for token */
                if (property->is_host_token)
                        result_ptr = stpncpy(result_ptr, LA_HOST_TOKEN_REPL,
                                        LA_HOST_TOKEN_REPL_LEN);
                else
                        result_ptr = stpncpy(result_ptr, LA_TOKEN_REPL, LA_TOKEN_REPL_LEN);

		start_pos = property->pos + property->length;
		string_ptr = string + start_pos;

		property = (la_property_t *) property->node.succ;
	}

	/* Copy remainder of string - only if there's something left.
	 * Double-check just to bes sure we don't overrun any buffer */
	if (string_ptr - string < strlen(string))
	{
		/* strcpy() ok here because we definitley reserved enough space
		 */
		strcpy(result_ptr, string_ptr);
	}
	la_log(LOG_DEBUG, "convert_regex(%s)=%s\n", string, result);

	return result; 
}

/*
 * Returns length of token - i.e. number of characters until closing '>' is
 * found. In case string ends before closing '>', die with an error message.
 */

static size_t
token_length(const char *string)
{
	const char *ptr = string+1;

	while (*ptr)
	{
		if (*ptr == '<')
			die_semantic("Closing '>' of token missing\n");
		else if (*ptr == '>')
			return ptr-string+1;
		ptr++;
	}

	die_semantic("Closing '>' of token missing\n");

	return 0; //avoid warning
}

static size_t
scan_single_token(kw_list_t *property_list, const char *string, unsigned int pos,
		unsigned int subexpression)
{
	size_t length = token_length(string);

	if (length > 2) /* so it's NOT just "<>" */
	{
		la_debug("TOKEN: %s, %u, %u\n", string, length, subexpression);
		add_tail(property_list, (kw_node_t *)
				create_property_from_token(string, length, pos,
					subexpression));
	}

	return length;
}

/*
 * Scans pattern string for tokens. Adds found tokens to property_list.
 *
 * Return number of found tokens.
 */

static unsigned int
scan_tokens(kw_list_t *property_list, const char *string)
{
	const char *ptr = string;
	unsigned int subexpression = 0;
	unsigned int n_tokens = 0;

	if (!property_list || !string)
		die_hard("No property list or no string submitted");

	while (*ptr) {
		if (*ptr == '\\')
		{
			ptr+=2;
		}
		else if (*ptr == '(')
		{
			subexpression++;
			ptr++;
		}
		else if (*ptr == '<')
		{
			n_tokens++;
			subexpression++;
			ptr += scan_single_token(property_list, ptr, ptr-string,
					subexpression);
		}
		else
			ptr++;
	}

	return n_tokens;
}

/*
 * Create and initalize new la_pattern_t.
 */

la_pattern_t *
create_pattern(const char *string_from_configfile, la_rule_t *rule)
{
	unsigned int n_properties;

	la_pattern_t *result = (la_pattern_t *) xmalloc(sizeof(la_pattern_t));
	
	result->rule = rule;
	result->properties = create_list();
	n_properties = scan_tokens(result->properties, string_from_configfile);
	result->string = convert_regex(string_from_configfile,
			result->properties, n_properties);

	result->regex = (regex_t *) xmalloc(sizeof(regex_t));
	int r = regcomp(result->regex, result->string, REG_EXTENDED);
	if (r)
	{
		// TODO: improve error handling
		die_err("Error compiling regex: %d\n", r);
	}

	return result;

}


/* vim: set autowrite expandtab: */
