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
#include <stdio.h>
#include <stdbool.h>

#include "logactiond.h"


void
assert_source_ffl(const la_source_t *source, const char *func,
                const char *file, unsigned int line)
{
        if (!source)
                die_hard("%s:%u: %s: Assertion 'source' failed. ", file, line, func);
        if (!source->location)
                die_hard("%s:%u: %s: Assertion 'source->location' failed. ", file, line, func);
}

/*
 * Call handle_log_line_for_rule() for each of the sources rules
 */

void
handle_log_line(const la_source_t *source, const char *line,
                const char *systemd_unit)
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
handle_new_content(const la_source_t *source)
{
        assert_source(source); assert(source->file);
        la_vdebug("handle_new_content(%s)", source->location);

        /* TODO: less random number? */
        size_t linebuffer_size = DEFAULT_LINEBUFFER_SIZE;
        char *linebuffer = alloca(linebuffer_size);

        /* TODO: can't remember why this extra read before the loop could be
         * necessary?!? */
        ssize_t num_read = getline(&linebuffer, &linebuffer_size, source->file);
        if (num_read==-1)
        {
                if (feof(source->file))
                {
                        /* What was the reason for this? I can't remember :-O */
                        fseek(source->file, 0, SEEK_END);
                        return true;
                }
                else
                        return false;
        }
        handle_log_line(source, linebuffer, NULL);

        for (;;)
        {
                num_read = getline(&linebuffer, &linebuffer_size,
                                source->file);
                if (num_read==-1)
                {
                        if (feof(source->file))
                                return true;
                        else
                                return false;
                }
                handle_log_line(source, linebuffer, NULL);
        }
}

la_source_group_t *
create_source_group(const char *name, const char *glob_pattern, const char *prefix)
{
        assert(name);
        la_debug("create_source_group(%s, %s, %s)", name, glob_pattern, prefix);

        la_source_group_t *result;

        result = xmalloc(sizeof(la_source_group_t));
        result->name = xstrdup(name);
        result->glob_pattern = xstrdup(glob_pattern);
        result->prefix = xstrdup(prefix);
        result->sources = xcreate_list();
        result->rules = xcreate_list();
        result->systemd_units = NULL;

        return result;
}

/*
 * Create a new la_source for the given filename, wd. But don't add to
 * la_config->sources.
 */

la_source_t *
create_source(la_source_group_t *source_group, const char *location)
{
        assert(source_group); assert(location);
        la_debug("create_source(%s, %s)", source_group->name, location);

        la_source_t *result;

        result = xmalloc(sizeof(la_source_t));
        result->source_group = source_group;
        result->location = xstrdup(location);
        result->parent_dir = NULL;
        result->file = NULL;
        result->active = false;

        /* Only used by inotify.c */
        result->wd = 0;
        result->parent_wd = 0;

        assert_source(result);
        return result;
}

/*
 * Free single source. Does nothing when argument is NULL. Expects source->file
 * to be NULL, i.e. source file must be unwatch_source()ed manually.
 */

void
free_source(la_source_t *source)
{
        la_vdebug("free_source()");
        if (!source)
                return;

        assert(!source->file);

        free(source->location);
        free(source->parent_dir);

        free(source);
}

void
free_source_group(la_source_group_t *source_group)
{
        if (!source_group)
                return;

        la_vdebug("free_source_group(%s)", source_group->name);

        free(source_group->name);
        free(source_group->glob_pattern);

        for (la_source_t *tmp;
                        (tmp = REM_SOURCES_HEAD(source_group->sources));)
                free_source(tmp);
        free(source_group->sources);

        free_rule_list(source_group->rules);

        free(source_group->prefix);

#if HAVE_LIBSYSTEMD
        if (source_group->systemd_units)
        {
                for (kw_node_t *tmp; (tmp = rem_head(source_group->systemd_units));)
                {
                        free(tmp->name);
                        free(tmp);
                }
                free(source_group->systemd_units);
        }
#endif /* HAVE_LISTSYSTEMD */

        free(source_group);
}

void
free_source_group_list(kw_list_t *list_list)
{
        la_vdebug("free_source_group_list()");

        if (!list_list)
                return;
        assert_list(list_list);

        for (la_source_group_t *tmp;
                        (tmp = REM_SOURCE_GROUPS_HEAD(list_list));)
                free_source_group(tmp);

        free(list_list);
}

/*
 * Find existing la_source for a given filename, return NULL if no la_source exists yet
 */

la_source_group_t
*find_source_group_by_location(const char *location)
{
        assert(location);
        assert(la_config); assert_list(la_config->source_groups);
        la_debug("find_source_group_by_location(%s)", location);

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
*find_source_group_by_name(const char *name)
{
        assert(name);
        assert(la_config); assert_list(la_config->source_groups);
        la_debug("find_source_group_by_name(%s)", name);

        for (la_source_group_t *source_group = ITERATE_SOURCE_GROUPS(la_config->source_groups);
                        (source_group = NEXT_SOURCE_GROUP(source_group));)
        {
                if (!strcmp(name, source_group->name))
                        return source_group;
        }

        return NULL;
}

/* vim: set autowrite expandtab: */
