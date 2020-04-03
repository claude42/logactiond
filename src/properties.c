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
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>

#include "logactiond.h"

void
assert_property_ffl(const la_property_t *property, const char *func,
                const char *file, unsigned int line)
{
        if (!property)
                die_hard("%s:%u: %s: Assertion 'property' failed. ", file,
                                line, func);
        if (!property->name)
                die_hard("%s:%u: %s: Assertion 'property->name' failed.", file,
                                line, func);
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
        assert(string);
        la_vdebug("token_length(%s)", string);

        const char *ptr = string+1;

        while (*ptr)
        {
                if (*ptr == '%')
                        return ptr-string+1;
                ptr++;
        }

        die_hard("Closing '%%' of token missing!");

        assert(false);
        return 0; // avoid compiler warning
}

/*
 * Go through property_list and find property with the same name as given as
 * second parameter. If such a property is found, return the whole property.
 * Return NULL otherwise. Also return NULL in case property_list is NULL.
 */

la_property_t *
get_property_from_property_list(const kw_list_t *property_list, const char *name)
{
        assert(name);
        la_vdebug("get_property_from_property_list(%s)", name);

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
 *
 * Note: will also return NULL if property is found but its value is NULL!
 *
 * Noet 2: will also return NULL if property_list is NULL
 */

const char *
get_value_from_property_list(const kw_list_t *property_list, const char *name)
{
        const la_property_t *property = get_property_from_property_list(
                                property_list, name);

        return property ? property->value : NULL;
}

/*
 * Duplicate string and onvert to lower case. Also die if non alpha-numeric
 * character is found.
 */

static char *
dup_str_and_tolower(const char *s, const size_t n)
{
        assert(s); assert(n>1);
        la_vdebug("dup_str_and_tolower(%s, %u)", s, n);
        const char *src = s;
        char *result = xmalloc(n+1);
        char *dst = result;

        while (src < s+n)
        {
                if (!isalnum(*src))
                        /* will print out partially converted name :-/ */
                        die_hard("Invalid property name %s!", s);
                *dst++ = tolower((unsigned char) *src++);
        }
        *dst = '\0';
        return result;
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

static la_property_t *
create_property_from_token(const char *name, const size_t length,
                const unsigned int pos, la_rule_t *rule)
{
        assert(name); assert(length>2);
        la_vdebug("create_property_from_token(%s)", name);

        la_property_t *result = xmalloc(sizeof(la_property_t));

        result->name = dup_str_and_tolower(name+1, length-2);
        result->value = NULL;

        result->is_host_property = false;
        if (!strcmp(result->name, LA_HOST_TOKEN))
        {
                result->is_host_property = true;
                result->replacement = xstrdup(LA_HOST_TOKEN_REPL);
        }
        else if (rule && rule->service && !strcmp(result->name, LA_SERVICE_TOKEN))
        {
                result->replacement = xstrdup(rule->service);
        }
        else
        {
                result->replacement = xstrdup(LA_TOKEN_REPL);
        }

        result->length = length;
        result->pos = pos;
        result->subexpression = 0;

        assert_property(result);
        return result;
}

/*
 * Creates a new property from token at *string with pos
 * Adds property to property list.
 *
 * String must point to first '%'
 */

la_property_t *
scan_single_token(const char *string, const unsigned int pos, la_rule_t *rule)
{
        assert(string);
        la_vdebug("scan_single_token(%s)", string);

        const size_t length = token_length(string);

        if (length > 2) /* so it's NOT just "%%" */
                return create_property_from_token(string, length, pos, rule);
        else
                return NULL;
}

la_property_t *
create_property_from_config(const char *name, const char *value)
{
        assert(name); assert(value);
        la_vdebug("create_property_from_config(%s, %s)", name, value);

        la_property_t *result = xmalloc(sizeof(la_property_t));

        result->name = dup_str_and_tolower(name, strlen(name));
        result->is_host_property = !strcmp(result->name, LA_HOST_TOKEN);
        result->value = xstrdup(value);
        result->replacement = NULL;
        
        assert_property(result);
        return result;
}

/*
 * Clones property. strdup()s name, value
 */

static la_property_t *
duplicate_property(const la_property_t *property)
{
        assert_property(property);
        la_vdebug("duplicate_property(%s)", property->name);
        la_property_t *result = xmalloc(sizeof(la_property_t));

        result->name = xstrdup(property->name);
        result->is_host_property = property->is_host_property;
        result->value = xstrdup(property->value);
        result->replacement = xstrdup(property->replacement);
        result->pos = property->pos;
        result->length = property->length;
        result->subexpression = property->subexpression;

        assert_property(result);
        return result;
}

kw_list_t *
dup_property_list(const kw_list_t *list)
{
        assert_list(list);
        la_vdebug("dup_property_list()");

        kw_list_t *result = xcreate_list();

        for (la_property_t *property = ITERATE_PROPERTIES(list);
                        (property = NEXT_PROPERTY(property));)
                add_tail(result, (kw_node_t *) duplicate_property(property));

        assert_list(result);
        return result;
}

/*
 * Free single property. Does nothing when argument is NULL
 */

void
free_property(la_property_t *property)
{
        if (!property)
                return;

        la_vdebug("free_property(%s, %s, %s)", property->name, property->value,
                        property->replacement);

        free(property->name);
        free(property->value);
        free(property->replacement);
        free(property);
}

/*
 * Free all properties in list
 */

void
empty_property_list(kw_list_t *list)
{
        la_vdebug("free_property_list()");
        if (!list)
                return;

        assert_list(list);
        for (la_property_t *tmp; (tmp = REM_PROPERTIES_HEAD(list));)
                free_property(tmp);

}

void
free_property_list(kw_list_t *list)
{
        empty_property_list(list);

        free(list);
}


/* vim: set autowrite expandtab: */
