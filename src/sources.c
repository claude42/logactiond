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
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "ndebug.h"
#include "configfile.h"
#include "logging.h"
#include "misc.h"
#include "rules.h"
#include "sources.h"


void
assert_source_ffl(const la_source_t *source, const char *func,
                const char *file, int line)
{
        if (!source)
                die_hard(false, "%s:%u: %s: Assertion 'source' failed.",
                                file, line, func);
        assert_source_group_ffl(source->source_group, func, file, line);
        if (!source->location)
                die_hard(false, "%s:%u: %s: Assertion 'source->location' "
                                "failed.", file, line, func);
}

void
assert_source_group_ffl(const la_source_group_t *source_group, const char *func,
                const char *file, int line)
{
        if (!source_group)
                die_hard(false, "%s:%u: %s: Assertion 'source_group' failed.",
                                file, line, func);
        if (!source_group->name)
                die_hard(false, "%s:%u: %s: Assertion 'source->name' failed.",
                                file, line, func);
        if (!source_group->glob_pattern)
                die_hard(false, "%s:%u: %s: Assertion 'source->location' "
                                "failed.", file, line, func);
        assert_list_ffl(source_group->sources, func, file, line);
        assert_list_ffl(source_group->rules, func, file, line);
}

/*
 * Call handle_log_line_for_rule() for each of the sources rules
 */

void
handle_log_line(const la_source_t *const source, const char *const line,
                const char *const systemd_unit)
{
        assert(line); assert_source(source);
        /* Don't do this otherwise this will end in an endless "log-loop" when
         * logging to syslog */
        /* la_debug("handle_log_line(%s, %s)", systemd_unit, line); */

        for (la_rule_t *rule = ITERATE_RULES(source->source_group->rules);
                        (rule = NEXT_RULE(rule));)
        {
                if (rule->enabled)
                {
                        /* In case we use systemd, check whether the systemd unit
                         * matches, otherwise we can save us going through all the
                         * pattern matching stuff */
#if HAVE_LIBSYSTEMD
                        if (!systemd_unit ||
                                        (rule->systemd_unit &&
                                         !strcmp(systemd_unit, rule->systemd_unit)))
#endif /* HAVE_LIBSYSTEMD */
                                handle_log_line_for_rule(rule, line);
                }
        }
}

/*
 * Read new content from file and hand over to handle_log_line()
 *
 * Reads until feof. Returns true if ended with feof, false if ended with
 * another error.
 */

bool
handle_new_content(const la_source_t *const source)
{
        assert_source(source); assert(source->file);
        la_vdebug_func(source->location);

        size_t linebuffer_size = 0;
        char *linebuffer = NULL;

        ssize_t num_read;

        while ((num_read = getline(&linebuffer, &linebuffer_size, source->file)) != -1)
                handle_log_line(source, linebuffer, NULL);

        const int result = feof(source->file);
        if (result)
                fseek(source->file, 0, SEEK_END);

        free(linebuffer);

        return result;
}

la_source_group_t *
create_source_group(const char *const name, const char *const glob_pattern,
                const char *const prefix)
{
        assert(name);
        la_debug("create_source_group(%s, %s, %s)", name, glob_pattern, prefix);

        la_source_group_t *const result = create_node(sizeof *result, 0, NULL);
        result->name = xstrdup(name);
        result->glob_pattern = xstrdup(glob_pattern);
        result->prefix = xstrdup(prefix);
        result->sources = create_list();
        result->rules = create_list();
#if HAVE_LIBSYSTEMD
        result->systemd_units = NULL;
#endif

        assert_source_group(result);
        return result;
}

/*
 * Create a new la_source for the given filename, wd. But don't add to
 * la_config->sources.
 */

la_source_t *
create_source(la_source_group_t *const source_group, const char *const location)
{
        assert_source_group(source_group); assert(location);
        la_debug("create_source(%s, %s)", source_group->name, location);

        la_source_t *const result = create_node(sizeof *result, 0, NULL);
        result->source_group = source_group;
        result->location = xstrdup(location);
        result->file = NULL;
        result->active = false;

#if HAVE_INOTIFY
        /* Only used by inotify.c */
        result->wd = 0;
        result->parent_wd = 0;
#endif /* HAVE_INOTIFY */

        assert_source(result);
        return result;
}

/*
 * Free single source. Does nothing when argument is NULL. Expects source->file
 * to be NULL, i.e. source file must be unwatch_source()ed manually.
 */

void
free_source(la_source_t *const source)
{
        la_vdebug_func(NULL);
        if (!source)
                return;

        assert(!source->file);

        free(source->location);

        free(source);
}

void
free_source_group(la_source_group_t *const source_group)
{
        if (!source_group)
                return;

        la_vdebug_func(source_group->name);

        free(source_group->name);
        free(source_group->glob_pattern);

        free_source_list(source_group->sources);
        free_rule_list(source_group->rules);

        free(source_group->prefix);

#if HAVE_LIBSYSTEMD
        if (source_group->systemd_units)
        {
                free_list(source_group->systemd_units, NULL);
                source_group->systemd_units = NULL;
        }
#endif /* HAVE_LISTSYSTEMD */

        free(source_group);
}


/*
 * Find existing la_source for a given filename, return NULL if no la_source exists yet
 */

la_source_group_t
*find_source_group_by_location(const char *const location)
{
        assert(location);
        assert(la_config); assert_list(la_config->source_groups);
        la_debug_func(location);

        for (la_source_group_t *source_group = ITERATE_SOURCE_GROUPS(la_config->source_groups);
                        (source_group = NEXT_SOURCE_GROUP(source_group));)
        {
                for (la_source_t *source = ITERATE_SOURCES(source_group->sources);
                                (source = NEXT_SOURCE(source));)
                        if (!strcmp(location, source->location))
                                return source_group;
        }

        return NULL;
}

/*
 * Find existing la_source for a given name, return NULL if no la_source exists yet
 */

la_source_group_t
*find_source_group_by_name(const char *const name)
{
        assert(name);
        assert(la_config); assert_list(la_config->source_groups);
        la_debug_func(name);

        for (la_source_group_t *source_group = ITERATE_SOURCE_GROUPS(la_config->source_groups);
                        (source_group = NEXT_SOURCE_GROUP(source_group));)
        {
                if (!strcmp(name, source_group->name))
                        return source_group;
        }

        return NULL;
}

void
reset_counts(void)
{
        assert_list(la_config->source_groups);

        for (la_source_group_t *source_group = ITERATE_SOURCE_GROUPS(la_config->source_groups);
                        (source_group = NEXT_SOURCE_GROUP(source_group));)
        {
                for (la_rule_t *rule = ITERATE_RULES(source_group->rules);
                                (rule = NEXT_RULE(rule));)
                        rule->invocation_count = rule->detection_count = 0;
        }
}

/* vim: set autowrite expandtab: */
