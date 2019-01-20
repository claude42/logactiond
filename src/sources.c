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

//#include <stdio.h>
//#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <syslog.h>

#include <libconfig.h>

#include "logactiond.h"

/* Buffer for reading log lines */
#define DEFAULT_LINEBUFFER_SIZE 8192

static char *linebuffer = NULL;
size_t linebuffer_size = DEFAULT_LINEBUFFER_SIZE;

static void
cut_newline(char *line)
{
	size_t len = strlen(line);

	if (line[len-1] == '\n')
		line[len-1] = '\0';
}

static void
handle_log_line(la_source_t *source, char *line)
{
	la_debug("handle_log_line(%s)\n", line);
	cut_newline(line);

	la_rule_t *rule = (la_rule_t *) source->rules->head.succ;

	while (rule->node.succ)
	{
		handle_log_line_for_rule(rule, line);
		rule = (la_rule_t *) rule->node.succ;
	}
}

void
handle_new_content(la_source_t *source)
{
	/* TODO: less random number? */
	if (!linebuffer)
		linebuffer = (char *) xmalloc(DEFAULT_LINEBUFFER_SIZE*sizeof(char));

	//if (feof(source->file))
	//{
		/* if we're directly EOF after a IN_MODIFY event, someone has
		 * done something weird to the log file - maybe truncatet it or
		 * written to the beginning. We have nore real chance of
		 * knowing. Before we risk piping the whole contents of a huge
		 * logfile through our daemon, we're playing it safe and rather
		 * skip everything. And wait for the next line.
		 */
		//if (fseek(source->file, 0, SEEK_END))
			//die_err("fseek failed");
		//la_debug("handle_new_content() - something weird happened\n");
		//return;
	//}

	ssize_t num_read = getline(&linebuffer, &linebuffer_size, source->file);
	if (num_read==-1)
	{
		if (feof(source->file))
		{
			fseek(source->file, 0, SEEK_END);
			return;
		}
		else
			die_err("Error while reading fromlogfile");
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
				die_err("Error while reading from logfile");
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
	source->file = fopen(source->location, "r");
	if (!source->file)
		die_err("fopen failed");
	if (fseek(source->file, 0, whence))
		die_err("fseek failed");

#if HAVE_INOTIFY
	watch_source_inotify(source);
#endif /* HAVE_INOTIFY */

}

void
unwatch_source(la_source_t *source)
{
	if (fclose(source->file))
		die_err("fclose failed");
	source->file = NULL;

#if HAVE_INOTIFY
	unwatch_source_inotify(source);
#endif /* HAVE_INOTIFY */

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
	result->name = name;
	result->location = location;
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