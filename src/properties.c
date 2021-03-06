/*
 *  logactiond - trigger actions based on logfile contents
 *  Copyright (C) 2019-2021 Klaus Wissmann

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
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>

#include "ndebug.h"
#include "logging.h"
#include "misc.h"
#include "patterns.h"
#include "properties.h"
#include "rules.h"
#include "syslog.h"

void
assert_property_ffl(const la_property_t *property, const char *func,
                const char *file, int line)
{
        if (!property)
                die_hard(false, "%s:%u: %s: Assertion 'property' failed. ",
                                file, line, func);
        if (property->replacement_braces < 0)
                die_hard(false, "%s:%u: %s: Assertion 'property->replacement_braces "
                                ">= 0' failed. ", file, line, func);
        if (property->pos < 0)
                die_hard(false, "%s:%u: %s: Assertion 'property->pos >= 0' failed. ",
                                file, line, func);
        /*if (property->length < 2)
                die_hard(false, "%s:%u: %s: Assertion 'property->length >= 2' failed. ",
                                file, line, func);*/
        if (property->subexpression < 0)
                die_hard(false, "%s:%u: %s: Assertion 'property->subexpression "
                                ">= 0' failed. ", file, line, func);
}

/*
 * Returns length of token - i.e. number of characters until closing '%' is
 * found. In case string ends before closing '%', die with an error message.
 *
 * Length will include both '%'
 */

size_t
token_length(const char *const string)
{
        assert(string); assert(*string == '%');
        la_vdebug_func(string);

        for (const char *ptr = string + 1; *ptr; ptr++)
        {
                if (*ptr == '%')
                        return ptr-string+1;
        }

        die_hard(false, "Closing '%%' of token missing!");

        assert(false);
        return 0; // avoid compiler warning
}

/*
 * Go through property_list and find property with the same name as given as
 * second parameter. If such a property is found, return the whole property.
 * Return NULL otherwise. Also return NULL in case property_list is NULL.
 */

la_property_t *
get_property_from_property_list(const kw_list_t *const property_list,
                const char *const name)
{
        assert(name);
        la_vdebug_func(name);

        if (!property_list)
                return NULL;
        assert_list(property_list);

        FOREACH(la_property_t, result, property_list)
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
get_value_from_property_list(const kw_list_t *const property_list,
                const char *const name)
{
        assert_list(property_list); assert(name);
        const la_property_t *const property = get_property_from_property_list(
                                property_list, name);

        return property ? property->value : NULL;
}

/*
 * Will copy src to test until delim is reached.  Will copy at most
 * MAX_PROP-SIZE - 1 bytes; less if src is shorter. Will make sure dest ends
 * with a '\0' byte in any case.
 *
 * Will return number of characters copied.
 *
 * Will fail if strlen(src) >= MAX_PROP_SIZE (i.e. src + '\0' wouldn't have
 * fitted into dest.
 *
 * Will fail if non-alphanumeric character is detected.
 */
static size_t
copy_str_and_tolower(char *const dest, const char *const src,
                const char delim)
{
        assert(dest); assert(src);
        la_vdebug_func(src);

        size_t i;
        for (i = 0; i < MAX_PROP_SIZE - 1 && src[i] != delim; i++)
        {
                if (!isalnum(src[i]))
                        die_hard(false, "Invalid property name %s!", src);
                dest[i] = tolower(src[i]);
        }

        dest[i] = '\0';

        if (src[i] != delim)
                die_hard(false, "Property name longer than %u characters.",
                                MAX_PROP_SIZE);

        return i;
}

/* 
 * Returns number of '(' in a string. Will not count '\('.
 */

static int
count_open_braces(const char *const string)
{
        assert(string);
        la_vdebug_func(string);

        int result = 0;

        for (const char *ptr = string; *ptr; ptr++)
        {
                switch (*ptr)
                {
                case '\\':
                        ptr++;
                        if (!*ptr)
                                die_hard(false, "String ends with \\\\0");
                        break;
                case '(':
                        result++;
                        break;
                }
        }

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

la_property_t *
create_property_from_token(const char *const name, const int pos,
                const la_rule_t *const rule)
{
        assert(name); assert(*name == '%');
        la_vdebug_func(name);

        if (name[1] =='%') /* detected just "%%" */
                return NULL;

        la_property_t *const result = create_node(sizeof *result, 0, NULL);

        result->length = copy_str_and_tolower(result->name, name+1, '%') + 2;
        assert(result->length > 2);

        result->value[0] = '\0';

        result->is_host_property = false;
        if (!strcmp(result->name, LA_HOST_TOKEN))
        {
                result->is_host_property = true;
                result->replacement = xstrdup(LA_HOST_TOKEN_REPL);
                result->replacement_braces = LA_HOST_TOKEN_NUMBRACES;
        }
        else if (rule && rule->service && !strcmp(result->name, LA_SERVICE_TOKEN))
        {
                result->replacement = xstrdup(rule->service);
                /* sadly, service can in fact contain braces, e.g.
                 * "postfix/(submission/)?smtpd", therefore we have to count
                 * them */
                result->replacement_braces = count_open_braces(result->replacement);
        }
        else
        {
                result->replacement = xstrdup(LA_TOKEN_REPL);
                result->replacement_braces = LA_TOKEN_NUMBRACES;
        }

        result->pos = pos;
        result->subexpression = 0;

        assert_property(result);
        return result;
}

la_property_t *
create_property_from_config(const char *const name, const char *const value)
{
        assert(name); assert(strlen(name) > 0); assert(value);
        la_vdebug("create_property_from_config(%s, %s)", name, value);

        la_property_t *const result = create_node(sizeof *result, 0, NULL);

        copy_str_and_tolower(result->name, name, '\0');

        result->is_host_property = !strcmp(result->name, LA_HOST_TOKEN);
        if (string_copy(result->value,  MAX_PROP_SIZE, value, 0, '\0') == -1)
                die_hard(false, "Property value longer than %u charcters.",
                                MAX_PROP_SIZE);
        result->replacement = NULL;
        result->replacement_braces = 0;
        result->pos = 0;
        result->length = 0;
        result->subexpression = 0;

        assert_property(result);
        return result;
}

/*
 * Clones property. strdup()s name, value
 */

static la_property_t *
duplicate_property(const la_property_t *const property)
{
        assert_property(property);
        la_vdebug_func(property->name);
        la_property_t *const result = create_node(sizeof *result, 0, NULL);

        *result = *property;
        result->replacement = xstrdup(property->replacement);

        assert_property(result);
        return result;
}

void copy_property_list(kw_list_t *const dest, const kw_list_t *const source)
{
        assert_list(dest); assert_list(source);
        FOREACH(la_property_t, property, source)
                add_tail(dest, (kw_node_t *) duplicate_property(property));
}

kw_list_t *
dup_property_list(const kw_list_t *const list)
{
        la_vdebug_func(NULL);

        kw_list_t *const result = create_list();
        copy_property_list(result, list);

        return result;
}

/*
 * Free single property. Does nothing when argument is NULL
 */

void
free_property(la_property_t *const property)
{
        if (!property)
                return;

        la_vdebug("free_property(%s, %s, %s)", property->name, property->value,
                        property->replacement);

        free(property->replacement);
        free(property);
}


/* vim: set autowrite expandtab: */
