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
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <stdlib.h>

#include <libconfig.h>

#include "logactiond.h"
#include "nodelist.h"

void
assert_pattern_ffl(la_pattern_t *pattern, const char *func, char *file, unsigned int line)
{
        if (!pattern)
                die_hard("%s:%u: %s: Assertion 'pattern' failed. ", file, line, func);
        assert_rule_ffl(pattern->rule, func, file, line);
        assert_list_ffl(pattern->properties, func, file, line);
}

/* 
 * Returns number of '(' in string
 */

static unsigned int
count_open_braces(const char *string)
{
        assert(string);
        la_vdebug("count_open_braces(%s)", string);

        unsigned int result = 0;

        for (const char *ptr = string; *ptr; ptr++)
        {
                if (*ptr == '(')
                        result++;
        }

        return result;
}

/*
 * dst is a block of previously allocated memory
 * dst_len is the length of the previously allocated memory
 * dst_ptr points somewhere within that memory
 *
 * realloc_buffer() allocates additional memory in case dst_ptr + on_top
 * exceeds the previously allocated block of memory. New size will be
 * 2 * dst_len + on_topsize
 */

static void realloc_buffer(char **dst, char **dst_ptr, size_t *dst_len, size_t on_top)
{
        la_vdebug("realloc_buffer(%u, %u)", *dst_len, on_top);

        if (*dst_ptr + on_top >= *dst + *dst_len)
        {
                *dst_len = *dst_len * 2 + on_top;
                la_debug("realloc_buffer()=%u", *dst_len);

                void *tmp_ptr;
                tmp_ptr = realloc(*dst, *dst_len);
                *dst_ptr = *dst_ptr - *dst + tmp_ptr;
                *dst = tmp_ptr;
        }
}

/*
 * Replaces first occurance of "%HOST%" in string by "([.:[:xdigit:]]+)".
 * Replaces all other "%SOMETHING%" tokens by "(.+)".
 *
 * Returns newly allocated string, doesn't modify original.
 *
 * TODO 1: really no error handling necessary?
 * TODO 2: clumsy code, better directly assign converted string to
 * pattern->string instead of returning it
 */

static char*
convert_regex(const char *string, la_pattern_t *pattern)
{
        assert(string);
        la_vdebug("convert_regex(%s)", string);

        size_t dst_len = 2 * strlen(string);
        char *result = xmalloc(dst_len);
        char *dst_ptr = result;
        const char *src_ptr = string;
        unsigned int subexpression = 0;
        bool has_host_token = false;

        while (*src_ptr)
        {
                if (*src_ptr == '%')
                {
                        la_property_t *new_prop =
                                scan_single_token(src_ptr, src_ptr-string);
                        if (new_prop)
                        {
                                // If we are here, we've detected a real token
                                // (and not just "%%").

                                // Make sure we only have one %HOST% token per
                                // pattern. Die otherwise.

                                if (new_prop->is_host_property)
                                {
                                        if (has_host_token)
                                                die_hard("Only one %HOST% token "
                                                                "allowed er pattern!");
                                        has_host_token = true;
                                }

                                // Count open braces a.) to determine whether
                                // we need this property for scanning at all
                                // and b.) to correctly update the subexpression
                                // count.
                                //
                                // a.) currently doesn't make to much sense, as
                                // the only two possible replacements always
                                // contain braces but this might change in the
                                // future.
                                //
                                // Use case Use case: logactiond has special,
                                // builtin %SOMETHING% variables which can be
                                // used in pattern definitions, e.g. think
                                // %HOSTNAME% being replaced by the local
                                // hostname.
                                unsigned int braces = count_open_braces(
                                                new_prop->replacement);

                                if (braces)
                                {
                                        if (subexpression + 1 >= MAX_NMATCH)
                                                die_hard("subexpression > MAX_NMATCH");

                                        new_prop->subexpression = subexpression + 1;
                                        add_tail(pattern->properties, (kw_node_t *)
                                                        new_prop);
                                        subexpression += braces;
                                }

                                // Finally replace the token by the
                                // corresponding replacement in the result
                                // string and increment src_ptr and dst_ptr
                                // accordingly (and of course make sure we have
                                // enough space...)
                                size_t repl_len = strlen(new_prop->replacement);
                                realloc_buffer(&result, &dst_ptr, &dst_len,
                                                repl_len);
                                dst_ptr = stpncpy(dst_ptr, new_prop->replacement,
                                                repl_len);
                                src_ptr += new_prop->length;

                                // Get rid of property if won't be needed
                                // anymore.
                                if (!braces)
                                        free(new_prop);
                        }
                        else
                        {
                                // In this case, we've only detected "%%", so
                                // copy one % and skip the other one
                                realloc_buffer(&result, &dst_ptr, &dst_len, 1);
                                *dst_ptr++ = '%';
                                src_ptr += 2;
                        }
                }
                else
                {
                        // Character other than "%" detected

                        // In case of '(', count sub expression
                        if (*src_ptr == '(')
                                subexpression++;

                        // In call cases copy character (and make sure we've
                        // enough space).
                        realloc_buffer(&result, &dst_ptr, &dst_len, 1);
                        *dst_ptr++ = *src_ptr++;
                }
        }

        *dst_ptr = 0;
        la_debug("convert_regex()=%s, subexpression=%u", result, subexpression);

        return result;
}

/*
 * Create and initalize new la_pattern_t.
 */

la_pattern_t *
create_pattern(const char *string_from_configfile, unsigned int num,
                la_rule_t *rule)
{
        assert(string_from_configfile); assert_rule(rule);
        la_debug("create_pattern(%s)", string_from_configfile);

        la_pattern_t *result = xmalloc(sizeof(la_pattern_t));

        result->num = num;
        result->rule = rule;
        result->properties = create_list();
        result->string = convert_regex(string_from_configfile, result);

        result->regex = xmalloc(sizeof(regex_t));
        int r = regcomp(result->regex, result->string, REG_EXTENDED | REG_NEWLINE);
        if (r)
        {
                // TODO: improve error handling
                die_err("Error %d compiling regex: %s!", r, result->string);
        }

        return result;
}

/*
 * Free single pattern. Does nothing when argument is NULL
 */

void
free_pattern(la_pattern_t *pattern)
{
        if (!pattern)
                return;

        assert_pattern(pattern);
        la_vdebug("free_pattern(%s)", pattern->string);

        free_property_list(pattern->properties);

        free(pattern->string);
        free(pattern->regex);

        free(pattern);
}

/*
 * Free all patterns in list
 */

void
free_pattern_list(kw_list_t *list)
{
        la_vdebug("free_pattern_list()");

        if (!list)
                return;

        for (la_pattern_t *tmp;
                        (tmp = REM_PATTERNS_HEAD(list));)
                free_pattern(tmp);

        free(list);
}

/* vim: set autowrite expandtab: */
