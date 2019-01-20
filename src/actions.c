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
//#include <stdlib.h>
#include <string.h>
//#include <sys/select.h>
#include <time.h>
#include <assert.h>
#include <limits.h>

#include <libconfig.h>

#include "logactiond.h"
#include "nodelist.h"

la_command_t *
create_begin_command(la_rule_t *rule, const char *begin, const char *end)
{
	la_command_t *result;

	assert(begin);

	{
		result = create_command(begin, rule->duration);
		if (end)
			result->end_command = create_command(end, -1);
	}

	return result;
}

la_command_t *
create_initialize_command(la_rule_t *rule, const char *initialize, const char *shutdown)
{
	la_command_t *result;

	assert(initialize);

	result = create_command(initialize, INT_MAX);
	result->rule = rule;
	if (shutdown)
	{
		result-> end_command = create_command(shutdown, -1);
		result->end_command->rule = rule;
	}

	return result;
}

/*
 * Create action based on initialize, shutdown, begin, end configuration.
 */

la_action_t *
create_action(const char *name, la_rule_t *rule, const char *initialize,
		const char *shutdown, const char *begin, const char *end)
{
	la_debug("create_action(%s)\n", name);

	la_action_t *result = (la_action_t *) xmalloc(sizeof(la_action_t));

	result->name = name;
	result->rule = rule;

	if (initialize)
	{
		result->initialize = create_initialize_command(rule, initialize, shutdown);
		trigger_command(result->initialize);
	}
	else
	{
		result->initialize = NULL;
	}

	if (begin)
		result->begin = create_begin_command(rule, begin, end);
	else
		result->begin = NULL;

	return result;
}

/* vim: set autowrite expandtab: */