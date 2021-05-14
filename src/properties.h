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

#ifndef __properties_h
#define __properties_h

#include <config.h>

#include "ndebug.h"
#include "rules.h"

#define LA_TOKEN_REPL "(.+)"
#define LA_TOKEN_NUMBRACES 1

#define LA_HOST_TOKEN "host"
#define LA_HOST_TOKEN_REPL "([.:[:xdigit:]]+)"
#define LA_HOST_TOKEN_NUMBRACES 1
#define LA_SERVICE_TOKEN "service"

#define LA_RULENAME_TOKEN "rulename"
#define LA_SOURCENAME_TOKEN "sourcename"
#define LA_PATTERNNAME_TOKEN "patternname"
#define LA_IPVERSION_TOKEN "ipversion"

#define MAX_PROP_SIZE 128

#ifdef NDEBUG
#define assert_property(PROPERTY) (void)(0)
#else /* NDEBUG */
#define assert_property(PROPERTY) assert_property_ffl(PROPERTY, __func__, __FILE__, __LINE__)
#endif /* NDEBUG */

#define empty_property_list(list) \
        empty_list(list, (void (*)(void *const)) free_property)

#define free_property_list(list) \
        free_list(list, (void (*)(void *const)) free_property)

/*
 * la_property_s
 */

typedef struct la_property_s la_property_t;
struct la_property_s
{
        struct kw_node_s node;
        /* name of the property (for matched tokens: without the '%'s) */
        char name[MAX_PROP_SIZE];
        /* Property created from HOST token */
        bool is_host_property;
        /* Different uses:
         * - when used for config file properties, this is simply the value
         *   assigned to the property in the config file
         * - when used when matching a log line to a regex, this is the matched
         *   value from the log line
         * - when used as an action token, this is the value taken from the
         *   original token
         */
        char value[MAX_PROP_SIZE];

        /* Only for tokens matching a log line. Specifies the regex that the
         * %token% should be replaced with.
         */
        char *replacement;
        int replacement_braces;

        /* The following  members will only be used when properties are
         * obtained from log lines matching tokens or in action strings.
         */

        /* Position in original string. Points to innitial '%'!.
         * Only for use in convert_regex() */
        int pos;
        /* Length of token including the two '%'. Saves us a few strlen() calls in
         * convert_regex()... */
        size_t length;

        /* The following members will only be used when matching log lines.  */

        /* Number of the subexpression this token represents in the regular
         * expression.
         */
        int subexpression;
};

void assert_property_ffl(const la_property_t *property, const char *func,
                const char *file, int line);

size_t token_length(const char *string);

la_property_t *get_property_from_property_list(const kw_list_t *property_list,
                const char *name);

const char *get_value_from_property_list(const kw_list_t *property_list,
                const char *name);

la_property_t *create_property_from_token(const char *name,
                const int pos, const la_rule_t *rule);

la_property_t *create_property_from_config(const char *name, const char *value);

void copy_property_list(kw_list_t *dest, const kw_list_t *source);

kw_list_t *dup_property_list(const kw_list_t *list);

void free_property(la_property_t *property);

#endif /* __properties_h */

/* vim: set autowrite expandtab: */
