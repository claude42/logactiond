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

#include <string.h>
#include <assert.h>
#include <syslog.h>

#include "logactiond.h"
#include "nodelist.h"

/*
 * Return value assigned to <HOST> property, NULL if not found.
 */

const char *
get_host_property_value(kw_list_t *property_list)
{
	for (la_property_t *property = (la_property_t *) property_list->head.succ;
			property->node.succ;
			property = (la_property_t *) property->node.succ)
	{
                if (property->is_host_property)
                        return property->value;
	}

	return NULL;
}

/*
 * Go through property_list and find property with the same name as given as
 * second parameter. If such a property is found, return the whole property.
 * Return NULL otherwise.
 */

la_property_t *
get_property_from_property_list(kw_list_t *property_list, const char *name)
{
        assert(name);

        if (!property_list)
                return NULL;

        la_property_t *result = (la_property_t *) property_list->head.succ;

        while (result->node.succ)
        {
                if (!strcmp(name, result->name))
                        return result;
                result = (la_property_t *) result->node.succ;
        }

        return NULL;
}

/*
 * Go through property_list and find property on the list with same name as
 * the property given as second parameter. If such a property is found, return
 * assigned value. Return NULL otherwise.
 */

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
        result->value = NULL;
        result->is_host_property = !strcmp(result->name, LA_HOST_TOKEN);
	result->length = length;
	result->pos = pos;
	result->subexpression = subexpression;

	return result;
}

la_property_t *
create_property_from_config(const char *name, const char *value)
{
	la_property_t *result = (la_property_t *) xmalloc(sizeof(la_property_t));

	result->name = xstrdup(name);
        result->is_host_property = !strcmp(result->name, LA_HOST_TOKEN);
	result->value = xstrdup(value);
	
	return result;
}

la_property_t *
create_property_from_action_token(const char *name, size_t length,
		unsigned int pos)
{
	return create_property_from_token(name, length, pos, 0);
}

/*
 * Clones property. strdup()s name, value
 */

static la_property_t *
duplicate_property(la_property_t *property)
{
	la_property_t *result = (la_property_t *)
		xmalloc(sizeof(la_property_t));

        result->name = property->name ? xstrdup(property->name) : NULL;
        result->is_host_property = property->is_host_property;
        result->value = property->value ? xstrdup(property->value) : NULL;
        result->pos = property->pos;
        result->length = property->length;
        result->subexpression = property->subexpression;

        return result;
}

kw_list_t *
dup_property_list(kw_list_t *list)
{
        kw_list_t *result = create_list();

	for (la_property_t *property = (la_property_t *) list->head.succ;
			property->node.succ;
			property = (la_property_t *) property->node.succ)
                add_tail(result, (kw_node_t *) duplicate_property(property));

        return result;
}


/* vim: set autowrite expandtab: */
