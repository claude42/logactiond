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


void
assert_source(la_source_t *source)
{
        assert(source);
        assert(source->name);
        assert(source->type == LA_SOURCE_TYPE_SYSTEMD || source->location);
        assert_list(source->rules);
        assert(source->type > LA_SOURCE_TYPE_UNDEFINED && source->type <= LA_SOURCE_TYPE_SYSTEMD);
}

/*
 * If string ends with a newline, replace this by \0
 *
 * line must not be NULL.
 */

static void
cut_newline(const char *line)
{
        assert(line);
        la_debug("cut_newline()\n");
        return;

	/*size_t len = strlen(line);

	if (line[len-1] == '\n')
		line[len-1] = '\0';*/
}

/*
 * Call handle_log_line_for_rule() for each of the sources rules
 */

void
handle_log_line(la_source_t *source, const char *line)
{
        assert(line); assert_source(source);
	la_debug("handle_log_line(%s)\n", line);
	cut_newline(line);

        for (la_rule_t *rule = (la_rule_t *) source->rules->head.succ;
                        rule->node.succ;
                        rule = (la_rule_t *) rule->node.succ)
	{
		handle_log_line_for_rule(rule, line);
	}
}


static void
open_source_file(la_source_t *source, int whence)
{
        assert (source);

	source->file = fopen(source->location, "r");
	if (!source->file)
		die_err("fopen failed");
	if (fseek(source->file, 0, whence))
		die_err("fseek failed");
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
        la_debug("watch_source(%s)\n", source->name);

        switch (source->type)
        {
                case LA_SOURCE_TYPE_POLLING:
                        die_hard("Source type 'polling' not supported yet.\n");
                        break;
                case LA_SOURCE_TYPE_INOTIFY:
#if HAVE_INOTIFY
                        open_source_file(source, whence);
                        watch_source_inotify(source);
#else /* HAVE_INOTIFY */
                        die_hard("Source type 'inotify' not supported.\n");
#endif /* HAVE_INOTIFY */
                        break;
                case LA_SOURCE_TYPE_SYSTEMD:
#if HAVE_LIBSYSTEMD
                        watch_source_systemd(source);
#else /* HAVE_LIBSYSTEMD */
                        die_hard("Source type 'systemd' not supported.\n");
#endif /* HAVE_LIBSYSTEMD */
                        break;
        }
}

static void
close_source_file(la_source_t *source)
{
        assert (source);

	if (fclose(source->file))
		die_err("fclose failed");
	source->file = NULL;
}

/*
 * Unwatch a previously watched file
 */

void
unwatch_source(la_source_t *source)
{
        assert(source);
        la_debug("unwatch_source(%s)\n", source->name);


        switch (source->type)
        {
                case LA_SOURCE_TYPE_POLLING:
                        die_hard("Source type 'polling' not supported yet.\n");
                        break;
                case LA_SOURCE_TYPE_INOTIFY:
#if HAVE_INOTIFY
                        close_source_file(source);
                        unwatch_source_inotify(source);
#else /* HAVE_INOTIFY */
                        die_hard("Source type 'inotify' not supported.\n");
#endif /* HAVE_INOTIFY */
                        break;
                case LA_SOURCE_TYPE_SYSTEMD:
#if HAVE_LIBSYSTEMD
                        unwatch_source_systemd(source);
#else /* HAVE_LIBSYSTEMD */
                        die_hard("Source type 'systemd' not supported.\n");
#endif /* HAVE_LIBSYSTEMD */
                        break;
        }
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
*find_source(const char *location, la_sourcetype_t type)
{
	la_source_t *la_source;

	kw_node_t *i = get_list_iterator(la_config->sources);

	while ((la_source = (la_source_t *) get_next_node(&i)))
	{
                if (type == la_source->type)
                {
                        if (type == LA_SOURCE_TYPE_SYSTEMD ||
                                        !strcmp(location, la_source->location))
                                return la_source;
                }
	}

	return NULL;
}

/* vim: set autowrite expandtab: */
