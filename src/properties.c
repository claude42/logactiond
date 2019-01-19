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

//#include <regex.h>
//#include <stdio.h>
//#include <stdlib.h>
#include <string.h>
//#include <sys/select.h>
#include <assert.h>

#include "logactiond.h"
#include "nodelist.h"

const char *
get_value_from_property_list(kw_list_t *property_list, la_property_t *property)
{
	/* not sure whether property_list can't get NULL under normal
	 * circumstances */
	assert(property);

	if (!property_list)
		return NULL;

	la_property_t *result = (la_property_t *) property_list->head.succ;

	while (result->node.succ)
	{
		if(!strncmp(property->name, result->name, property->length))
			return result->value;
		result = (la_property_t *) result->node.succ;
	}

	return NULL;
}


/*
 * Create and initialize new la_property_t.
 *
 * Input string is the token name. String must point to the initial '<' and
 * doesn't not have to have the token's name null terminated but can be longer.
 * In la_property_t only the name without '<' and '>' will be saved (strdup()ed,
 * original will not be modified.
 *
 * Saved length includes '<' and '>' and will be saved as such in la_property_t.
 *
 * Pos is the offset to the beginning of the string, pointing to the initial
 * '<'
 */

la_property_t *
create_property_from_token(const char *name, size_t length, unsigned int pos,
		unsigned int subexpression)
{
	la_property_t *result = (la_property_t *)
		xmalloc(sizeof(la_property_t));

	result->name = xstrndup(name+1, length-2);
	result->length = length;
	result->pos = pos;
	result->subexpression = subexpression;

	return result;
}

/* FIXME: take care of strdup strings when necessary */

la_property_t *
create_property_from_config(const char *name, const char *value)
{
	la_property_t *result = (la_property_t *) xmalloc(sizeof(la_property_t));

	result->name = xstrdup(name);
	result->value = xstrdup(value);
	
	return result;
}

la_property_t *
create_property_from_action_token(const char *name, size_t length,
		unsigned int pos)
{
	return create_property_from_token(name, length, pos, 0);
}


/* vim: set autowrite expandtab: */
