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

#include <libconfig.h>

#include "logactiond.h"

static char *linebuffer = NULL;
size_t linebuffer_size = DEFAULT_LINEBUFFER_SIZE;

void
assert_source(la_source_t *source)
{
        assert(source);
        assert(source->name);
        assert(source->location);
        assert_list(source->rules);
}

/*
 * Call handle_log_line_for_rule() for each of the sources rules
 */

static void
handle_log_line(la_source_t *source, char *line)
{
        assert(line); assert_source(source);
        la_debug("handle_log_line(%s)", line);

        for (la_rule_t *rule = (la_rule_t *) source->rules->head.succ;
                        rule->node.succ;
                        rule = (la_rule_t *) rule->node.succ)
        {
                handle_log_line_for_rule(rule, line);
        }
}

/*
 * Read new content from file and hand over to handle_log_line()
 */

void
handle_new_content(la_source_t *source)
{
        assert_source(source);
        la_debug("handle_new_content(%s)", source->name);

        /* TODO: less random number? */
        if (!linebuffer)
                linebuffer = (char *) xmalloc(DEFAULT_LINEBUFFER_SIZE*sizeof(char));

        /* TODO: can't remember why this extra read before the loop could be
         * necessary?!? */
        ssize_t num_read = getline(&linebuffer, &linebuffer_size, source->file);
        if (num_read==-1)
        {
                if (feof(source->file))
                {
                        fseek(source->file, 0, SEEK_END);
                        return;
                }
                else
                        die_err("Reading from source \"%s\" failed", source->name);
        }
        handle_log_line(source, linebuffer);


        for (;;)
        {
                ssize_t num_read = getline(&linebuffer, &linebuffer_size, source->file);
                if (num_read==-1)
                {
                        if (feof(source->file))
                                break;
                        else
                                die_err("Reading from source \"%s\" failed", source->name);
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
        assert_source(source);
        la_debug("watch_source(%s)", source->name);

#ifndef NOWATCH
        source->file = fopen(source->location, "r");
        if (!source->file)
                die_err("Opening source \"%s\" failed", source->name);
        if (fseek(source->file, 0, whence))
                die_err("Seeking in source \"%s\" failed", source->name);

#if HAVE_INOTIFY
        watch_source_inotify(source);
#endif /* HAVE_INOTIFY */

#endif /* NOWATCH */
}

/*
 * Unwatch a previously watched file
 */

void
unwatch_source(la_source_t *source)
{
        assert(source);
        la_debug("unwatch_source(%s)", source->name);

#ifndef NOWATCH
        if (fclose(source->file))
                die_err("Closing source \"%s\" failed", source->name);
        source->file = NULL;

#if HAVE_INOTIFY
        unwatch_source_inotify(source);
#endif /* HAVE_INOTIFY */

#endif /* NOWATCH */
}

/*
 * Create a new la_source for the given filename, wd. But don't add to
 * la_config->sources.
 */

la_source_t *
create_source(const char *name, la_sourcetype_t type, const char *location)
{
        la_source_t *result;

        result = (la_source_t *) xmalloc(sizeof(la_source_t));
        result->name = xstrdup(name);
        result->location = xstrdup(location);
        result->type = type;
        result->rules = create_list();

        return result;
}

/*
 * Find existing la_source for a given filename, return NULL if no la_source exists yet
 */

la_source_t
*find_source_by_location(const char *location)
{
        la_source_t *la_source;
        la_source_t *result = NULL;

        kw_node_t *i = get_list_iterator(la_config->sources);

        while ((la_source = (la_source_t *) get_next_node(&i)))
        {
                if (!strcmp(location, la_source->location))
                {
                        result = la_source;
                        break;
                }
        }

        return result;
}

/* vim: set autowrite expandtab: */
