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
#include <stdlib.h>
#include <ctype.h>

#include "logactiond.h"
#include "nodelist.h"

void
assert_property(la_property_t *property)
{
        assert(property);
        assert(property->name);
}

/*
 * Returns length of token - i.e. number of characters until closing '%' is
 * found. In case string ends before closing '%', die with an error message.
 *
 * Length will include both '%'
 */

size_t
token_length(const char *string)
{
        const char *ptr = string+1;

        while (*ptr)
        {
                if (*ptr == '%')
                        return ptr-string+1;
                ptr++;
        }

        die_semantic("Closing '%%' of token missing!");

        return 0; // avoid warning
}


/*
 * Return value assigned to %HOST% property, NULL if not found.
 */

const char *
get_host_property_value(kw_list_t *property_list)
{
        for (la_property_t *property = ITERATE_PROPERTIES(property_list);
                        (property = NEXT_PROPERTY(property));)
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

        for (la_property_t *result = ITERATE_PROPERTIES(property_list);
                        (result = NEXT_PROPERTY(result));)
        {
                if (!strcmp(name, result->name))
                        return result;
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
        assert_property(property);

        if (!property_list)
                return NULL;

        for (la_property_t *result = ITERATE_PROPERTIES(property_list);
                        (result = NEXT_PROPERTY(result));)
        {
                if(!strncmp(property->name, result->name, property->length))
                        return result->value;
        }

        return NULL;
}

/*
 * Convert name to lower case. Also die if non alpha-numeric character is
 * found.
 */

static void convert_property_name(char *name)
{
        assert(name);
        la_debug("convert_property_name(%s)", name);

        char *ptr = name;

        for (; *ptr; ptr++)
        {
                if (!isalnum(*ptr))
                        /* will print out partially converted name :-/ */
                        die_hard("Invalid property name %s!", name);
                
                *ptr = tolower((unsigned char) *ptr);
        }
}


/*
 * Create and initialize new la_property_t.
 *
 * Input string is the token name. String must point to the initial '%' and
 * doesn't not have to have the token's name null terminated but can be longer.
 * In la_property_t only the name without thw two '%' will be saved (strdup()ed,
 * original will not be modified.
 *
 * Saved length includes the two '%' and will be saved as such in la_property_t.
 *
 * Pos is the offset to the beginning of the string, pointing to the initial
 * '%'
 */

la_property_t *
create_property_from_token(const char *name, size_t length, unsigned int pos,
                unsigned int subexpression)
{
        la_property_t *result = (la_property_t *)
                xmalloc(sizeof(la_property_t));

        result->name = xstrndup(name+1, length-2);
        convert_property_name(result->name);
        result->value = NULL;
        result->is_host_property = !strcmp(result->name, LA_HOST_TOKEN);
        result->length = length;
        result->pos = pos;
        result->subexpression = subexpression;

        return result;
}

/*
 * Creates a new property from token at *string with pos and subexpression.
 * Adds property to property list.
 *
 * String must point to first '%'
 * Set subexpression=0 in case of action tokens.
 */

size_t
scan_single_token(kw_list_t *property_list, const char *string, unsigned int pos,
                unsigned int subexpression)
{
        size_t length = token_length(string);

        if (length > 2) /* so it's NOT just "%%" */
        {
                add_tail(property_list, (kw_node_t *)
                                create_property_from_token(string, length, pos,
                                        subexpression));
        }

        return length;
}

la_property_t *
create_property_from_config(const char *name, const char *value)
{
        la_property_t *result = (la_property_t *) xmalloc(sizeof(la_property_t));

        result->name = xstrdup(name);
        convert_property_name(result->name);
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

        result->name = xstrdup(property->name);
        result->is_host_property = property->is_host_property;
        result->value = xstrdup(property->value);
        result->pos = property->pos;
        result->length = property->length;
        result->subexpression = property->subexpression;

        return result;
}

kw_list_t *
dup_property_list(kw_list_t *list)
{
        kw_list_t *result = create_list();

        for (la_property_t *property = ITERATE_PROPERTIES(list);
                        (property = NEXT_PROPERTY(property));)
                add_tail(result, (kw_node_t *) duplicate_property(property));

        return result;
}

void
free_property(la_property_t *property)
{
        assert_property(property);

        free(property->name);
        free(property->value);
}

void
free_property_list(kw_list_t *list)
{
        if (!list)
                return;

        for (la_property_t *tmp;
                        (tmp = REM_PROPERTIES_HEAD(list));)
                free_property(tmp);

        free(list);
}


/* vim: set autowrite expandtab: */
