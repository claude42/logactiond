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
#include <sys/select.h>
#include <syslog.h>
#include <assert.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#include <libconfig.h>

#include "logactiond.h"

static char *linebuffer = NULL;
size_t linebuffer_size = DEFAULT_LINEBUFFER_SIZE;

void
assert_source_ffl(la_source_t *source, const char *func, char *file, unsigned int line)
{
        if (!source)
                die_hard("%s:%u: %s: Assertion 'source' failed. ", file, line, func);
        if (!source->name)
                die_hard("%s:%u: %s: Assertion 'source->name' failed. ", file, line, func);
        if (!source->location)
                die_hard("%s:%u: %s: Assertion 'source->location' failed. ", file, line, func);
        assert_list_ffl(source->rules, func, file, line);
}

/*
 * Call handle_log_line_for_rule() for each of the sources rules
 */

void
handle_log_line(la_source_t *source, const char *line, const char *systemd_unit)
{
        assert(line); assert_source(source);
        la_debug("handle_log_line(%s, %s)", systemd_unit, line);

        for (la_rule_t *rule = ITERATE_RULES(source->rules);
                        (rule = NEXT_RULE(rule));)
        {
                if (!systemd_unit ||
                                (rule->systemd_unit &&
                                 !strcmp(systemd_unit, rule->systemd_unit)))
                        handle_log_line_for_rule(rule, line);
        }
}

/*
 * Read new content from file and hand over to handle_log_line()
 *
 * Reads until feof. Returns true if ended with feof, false if ended with
 * another error.
 */

bool
handle_new_content(la_source_t *source)
{
        assert_source(source);
        la_vdebug("handle_new_content(%s)", source->name);

        /* TODO: less random number? */
        if (!linebuffer)
                linebuffer = xmalloc(DEFAULT_LINEBUFFER_SIZE*sizeof(char));

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
                ssize_t num_read = getline(&linebuffer, &linebuffer_size, source->file);
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





/*
 * Create a new la_source for the given filename, wd. But don't add to
 * la_config->sources.
 */

la_source_t *
create_source(const char *name, const char *location, const char *prefix)
{
        assert(name);
        la_debug("create_source(%s, %s, %s)", name, location, prefix);

        la_source_t *result;

        result = xmalloc(sizeof(la_source_t));
        result->name = xstrdup(name);
        result->location = xstrdup(location);
        result->prefix = xstrdup(prefix);
        result->parent_dir = NULL;
        result->rules = xcreate_list();
        result->file = NULL;
        result->active = false;

        /* Only used by inotify.c */
        result->wd = 0;
        result->parent_wd = 0;

        /* Only used by systemd.c */
        result->systemd_units = NULL;

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
        if (!source)
                return;

        assert_source(source); assert(!source->file);
        la_vdebug("free_source(%s)", source->name);

        free_rule_list(source->rules);

        free(source->name);
        free(source->location);
        free(source->prefix);
        free(source->parent_dir);

        if (source->systemd_units)
        {
                for (kw_node_t *tmp; (tmp = rem_head(source->systemd_units));)
                {
                        free(tmp->name);
                        free(tmp);
                }
                free(source->systemd_units);
        }

        free(source);
}

/*
 * Free all sources in list
 */

void
empty_source_list(kw_list_t *list)
{
        la_vdebug("free_source_list()");

        if (!list)
                return;

        for (la_source_t *tmp;
                        (tmp = REM_SOURCES_HEAD(list));)
                free_source(tmp);
}

void
free_source_list(kw_list_t *list)
{
        empty_source_list(list);

        free(list);
}

/*
 * Find existing la_source for a given filename, return NULL if no la_source exists yet
 */

la_source_t
*find_source_by_location(const char *location)
{
        assert(location);
        la_debug("find_source_by_location(%s)", location);

        for (la_source_t *source = ITERATE_SOURCES(la_config->sources);
                        (source = NEXT_SOURCE(source));)
        {
                if (!strcmp(location, source->location))
                        return source;
        }

        return NULL;
}

/* vim: set autowrite expandtab: */
