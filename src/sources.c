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

static void
handle_log_line(la_source_t *source, char *line)
{
        assert(line); assert_source(source);
        la_vdebug("handle_log_line(%s)", line);

        for (la_rule_t *rule = ITERATE_RULES(source->rules);
                        (rule = NEXT_RULE(rule));)
        {
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
        handle_log_line(source, linebuffer);

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
                handle_log_line(source, linebuffer);
        }
}



/*
 * Add general watch for given filename.
 *
 * Returns la_watch_t
 */

void
watch_source(la_source_t *source, int whence)
{
        if (run_type == LA_UTIL_FOREGROUND)
                return;

        assert_source(source);
        la_debug("watch_source(%s)", source->name);

#ifndef NOWATCH
        source->file = fopen(source->location, "r");
        if (!source->file)
                die_err("Opening source \"%s\" failed", source->name);
        if (fstat(fileno(source->file), &(source->stats)) == -1)
                die_err("Stating source \"%s\" failed", source->name);
        if (fseek(source->file, 0, whence))
                die_err("Seeking in source \"%s\" failed", source->name);

        source->active = true;

#if HAVE_INOTIFY
        watch_source_inotify(source);
#else /* HAVE_INOTIFY */
        watch_source_polling(source);
#endif /* HAVE_INOTIFY */

#endif /* NOWATCH */
}

/*
 * Unwatch a previously watched file
 */

void
unwatch_source(la_source_t *source)
{
        if (run_type == LA_UTIL_FOREGROUND)
                return;

        assert_source(source); assert(source->file); assert(source->active);

        la_debug("unwatch_source(%s)", source->name);

#ifndef NOWATCH

#if HAVE_INOTIFY
        unwatch_source_inotify(source);
#else /* HAVE_INOTIFY */
        unwatch_source_polling(source);
#endif /* HAVE_INOTIFY */

        if (fclose(source->file))
                die_err("Closing source \"%s\" failed", source->name);
        source->file = NULL;
        source->active = false;

#endif /* NOWATCH */
}


/*
 * Create a new la_source for the given filename, wd. But don't add to
 * la_config->sources.
 */

la_source_t *
create_source(const char *name, la_sourcetype_t type, const char *location,
                const char *prefix)
{
        assert(name);
        la_debug("create_source(%s, %s, %s)", name, location, prefix);

        la_source_t *result;

        result = xmalloc(sizeof(la_source_t));
        result->name = xstrdup(name);
        result->location = xstrdup(location);
        result->prefix = xstrdup(prefix);
        result->parent_dir = NULL;
        result->type = type;
        result->rules = create_list();
        result->file = NULL;
        result->active = false;

#if HAVE_INOTIFY
        result->wd = 0;
        result->parent_wd = 0;
#endif /* HAVE_INOTIFY */


        assert_source(result);
        return result;
}

/*
 * Free single source. Does nothing when argument is NULL
 */

void
free_source(la_source_t *source)
{
        if (!source)
                return;

        assert_source(source);
        la_vdebug("free_source(%s)", source->name);

        if (source->file)
                unwatch_source(source);

        free_rule_list(source->rules);

        free(source->name);
        free(source->location);
        free(source->prefix);
        free(source->parent_dir);

        free(source);
}

/*
 * Free all sources in list
 */

void
free_source_list(kw_list_t *list)
{
        la_vdebug("free_source_list()");

        if (!list)
                return;

        for (la_source_t *tmp;
                        (tmp = REM_SOURCES_HEAD(list));)
                free_source(tmp);

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
