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

#include <sys/types.h>
#include <regex.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>

#include "ndebug.h"
#include "logging.h"
#include "misc.h"
#include "patterns.h"
#include "properties.h"
#include "rules.h"
#include "sources.h"

void
assert_pattern_ffl(const la_pattern_t *pattern, const char *func,
                const char *file, int line)
{
        if (!pattern)
                die_hard(false, "%s:%u: %s: Assertion 'pattern' failed. ",
                                file, line, func);
        if (pattern->num < 0)
                die_hard(false, "%s:%u: %s: Assertion 'pattern->num >= 0' failed. ",
                                file, line, func);
        assert_rule_ffl(pattern->rule, func, file, line);
        if (!pattern->string)
                die_hard(false, "%s:%u: %s: Assertion 'pattern->string' failed. ",
                                file, line, func);
        if (pattern->host_property)
                assert_property_ffl(pattern->host_property, func, file, line);
        assert_list_ffl(pattern->properties, func, file, line);
        if (pattern->detection_count < 0)
                die_hard(false, "%s:%u: %s: Assertion 'pattern->detection_count "
                                ">= 0' failed. ", file, line, func);
        if (pattern->invocation_count < 0)
                die_hard(false, "%s:%u: %s: Assertion 'pattern->invocation_count "
                                ">= 0' failed. ", file, line, func);
}

static void add_property(la_pattern_t *const pattern, la_property_t *const property)
{
        assert(pattern); assert_list(pattern->properties); assert_property(property);

        add_tail(pattern->properties, (kw_node_t *) property);
        if (property->is_host_property)
                pattern->host_property = property;
}

/*
 * Replaces first occurance of "%HOST%" in string by "([.:[:xdigit:]]+)".
 * Replaces all other "%SOMETHING%" tokens by "(.+)".
 *
 * Returns newly allocated string, doesn't modify original.
 *
 * TODO 1: really no error handling necessary?
 * pattern->string instead of returning it
 */

static void
convert_regex(const char *const string, la_pattern_t *const pattern)
{
        assert(string); assert(pattern); assert_rule(pattern->rule);
        assert_list(pattern->properties);
        la_vdebug_func(string);

        size_t dst_len = 1000;
        char *result = xmalloc(dst_len);
        char *dst_ptr = result;
        const char *src_ptr = string;
        int subexpression = 0;

        while (*src_ptr)
        {
                la_property_t *new_prop;
                switch (*src_ptr)
                {
                case '%':
                        new_prop = create_property_from_token(src_ptr,
                                        src_ptr-string, pattern->rule);
                        if (new_prop)
                        {
                                assert_property(new_prop);
                                // If we are here, we've detected a real token
                                // (and not just "%%").

                                // Make sure we only have one %HOST% token per
                                // pattern. Die otherwise.

                                if (new_prop->is_host_property &&
                                                pattern->host_property)
                                        die_hard(false, "Only one %%HOST%% token "
                                                        "allowed per pattern!");

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
                                // Use case: logactiond has special,
                                // builtin %SOMETHING% variables which can be
                                // used in pattern definitions, e.g. think
                                // %HOSTNAME% being replaced by the local
                                // hostname.
                                if (new_prop->replacement_braces)
                                {
                                        new_prop->subexpression = subexpression + 1;
                                        add_property(pattern, new_prop);
                                        subexpression += new_prop->replacement_braces;
                                        if (subexpression >= MAX_NMATCH)
                                                die_hard(false, "Too many subexpressions "
                                                                "in regex \"%s\"!", string);
                                }

                                // Finally replace the token by the
                                // corresponding replacement in the result
                                // string and increment src_ptr and dst_ptr
                                // accordingly (and of course make sure we have
                                // enough space...)
                                const size_t repl_len = xstrlen(new_prop->replacement);
                                realloc_buffer(&result, &dst_ptr, &dst_len,
                                                repl_len);
                                dst_ptr = stpncpy(dst_ptr, new_prop->replacement,
                                                repl_len);
                                src_ptr += new_prop->length;

                                // Get rid of property if won't be needed
                                // anymore.
                                if (!new_prop->replacement_braces)
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
                        break;
                case '\\':
                        // In case of '\', copy next character without any
                        // interpretation unless next character is \0...
                        if (*(src_ptr+1) == '\0') 
                                die_hard(false, "Last character of regex \"%s\" "
                                                "is \\!", string);
                        realloc_buffer(&result, &dst_ptr, &dst_len, 2);
                        *dst_ptr++ = *src_ptr++;
                        *dst_ptr++ = *src_ptr++;
                        break;
                case '(':
                        // In case of '(', count sub expression
                        if (subexpression++ >= MAX_NMATCH)
                                die_hard(false, "Too many subexpressions in "
                                                "regex \"%s\"!", string);
                        // intentional fall through!
                default:
                        // simply copy all other characters
                        realloc_buffer(&result, &dst_ptr, &dst_len, 1);
                        *dst_ptr++ = *src_ptr++;
                        break;
                }
        }

        *dst_ptr = 0;
        la_vdebug("convert_regex(%s)=%s, subexpression=%u", string, result, subexpression);

        pattern->string = result;
}

/*
 * Return nice error message for regcomp()
 */

static void
die_re(const int errcode, const regex_t *const preg)
{
        const size_t errbuf_size = 255;
        char error_msg[errbuf_size];

        regerror(errcode, preg, error_msg, errbuf_size);

        die_hard(true, "%s", error_msg);
}

/*
 * Create and initalize new la_pattern_t.
 */

la_pattern_t *
create_pattern(const char *const string_from_configfile,
                const int num, la_rule_t *const rule)
{
        assert(string_from_configfile); assert_rule(rule);
        la_vdebug_func(string_from_configfile);

        char *const full_string = concat(rule->source_group->prefix,
                        string_from_configfile);
        assert(full_string);
        la_vdebug("full_string=%s", full_string);

        la_pattern_t *const result = xmalloc(sizeof *result);

        result->node.pri = 0;
        result->num = num;
        result->rule = rule;
        result->host_property = NULL;
        result->properties = create_list();
        convert_regex(full_string, result);
        free(full_string);

        const int r = regcomp(&(result->regex), result->string, REG_EXTENDED |
                        REG_NEWLINE);
        if (r)
                die_re(r, &(result->regex));

        result->detection_count = result->invocation_count = 0;

        assert_pattern(result);
        return result;
}

/*
 * Free single pattern. Does nothing when argument is NULL
 */

void
free_pattern(la_pattern_t *const pattern)
{
        if (!pattern)
                return;

        la_vdebug_func(pattern->string);

        free_property_list(pattern->properties);

        free(pattern->string);

        regfree(&(pattern->regex));

        free(pattern);
}

/*
 * Free all patterns in list
 */

void
free_pattern_list(kw_list_t *const list)
{
        la_vdebug_func(NULL);

        if (!list)
                return;

        for (la_pattern_t *tmp;
                        (tmp = REM_PATTERNS_HEAD(list));)
                free_pattern(tmp);

        free(list);
}

/* vim: set autowrite expandtab: */
