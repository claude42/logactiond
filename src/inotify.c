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

#if HAVE_INOTIFY

//#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
//#include <sys/select.h>
#include <unistd.h>
#include <syslog.h>
#include <assert.h>
#include <syslog.h>
#include <libgen.h>

#include <libconfig.h>

//#include "dirname.h"

#include "logactiond.h"

/* Buffer for reading inotify events */
#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

static int inotify_fd;

static void
la_debug_inotify_event(struct inotify_event *event, uint32_t monitored)
{
	char *str;

	if (event->mask & IN_ACCESS)
		str = "IN_ACCESS";
	else if (event->mask & IN_ATTRIB)
		str = "IN_ATTRIB)";
	else if (event->mask & IN_CLOSE_WRITE)
		str = "IN_CLOSE_WRITE";
	else if (event->mask & IN_CLOSE_NOWRITE)
		str = "IN_CLOSE_NOWRITE";
	else if (event->mask & IN_CREATE)
		str = "IN_CREATE";
	else if (event->mask & IN_DELETE)
		str = "IN_DELETE";
	else if (event->mask & IN_DELETE_SELF)
		str = "IN_DELETE_SELF";
	else if (event->mask & IN_MODIFY)
		str = "IN_MODIFY";
	else if (event->mask & IN_MOVE_SELF)
		str = "IN_MOVE_SELF";
	else if (event->mask & IN_MOVED_FROM)
		str = "IN_MOVED_FROM";
	else if (event->mask & IN_MOVED_TO)
		str = "IN_MOVED_TO";
	else if (event->mask & IN_OPEN)
		str = "IN_OPEN";

	if (event->mask & monitored)
		la_debug("%u: %s (%s)%s\n", event->wd, str, event->name, "");
	else
		la_debug("%u: %s (%s)%s\n", event->wd, str, event->name, " - ignored");
}

/*
 * Removes inotify watch for file but not for parent directory
 */

void
unwatch_source_inotify(la_source_t *source)
{
	la_debug("unwatch_source_inotify()\n");
	if (inotify_rm_watch(inotify_fd, source->wd))
		la_log_errno(LOG_ERR, "unwatch source failed");
	source->wd = 0;
}


/*
 * Find existing la_source for a given wd (for the parent directory) and file
 * name.
 * NULL if no la_source exists yet
 */

static la_source_t *
find_source_by_parent_wd(int parent_wd, char *file_name)
{
	assert(parent_wd); assert(file_name);

	kw_node_t *i = get_list_iterator(la_config->sources);

	la_source_t *source;
	while (source = (la_source_t *) get_next_node(&i))
	{
		if (source->parent_wd == parent_wd)
		{
			/* all praise basename/dirname */
			char *tmp = strdup(source->location);
			char *base_name = basename(tmp);
			free(tmp);
			if (!strcmp(file_name, base_name))
				return source;
		}
	}

	return NULL;
}

/*
 * Find existing la_source for a given wd (for the file itself), return NULL if
 * no la_source exists yet
 */

static la_source_t *
find_source_by_file_wd(int file_wd)
{
	kw_node_t *i = get_list_iterator(la_config->sources);

	la_source_t *source;
	while (source = (la_source_t *) get_next_node(&i))
	{
		if (source->wd == file_wd)
		{
			return source;
		}
	}

	return NULL;
}

/*
 *
 */

static void
watched_file_created(la_source_t *source)
{
	/* unwatch not necessary in case of a previous IN_DELETE */
	if (source->file)
		unwatch_source(source);
	watch_source(source, SEEK_SET);
	handle_new_content(source);
}

static void
watched_file_moved_to(la_source_t *source)
{
	/* unwatch not necessary in case of a previous IN_DELETE */
	if (source->file)
		unwatch_source(source);
	/* ignore existing content when fiel was moved here - better safe than
	 * sorry */
	watch_source(source, SEEK_END);
}

static void
watched_file_deleted(la_source_t *source)
{
	unwatch_source(source);
}


static void
handle_inotify_directory_event(struct inotify_event *event)
{
	la_debug_inotify_event(event, IN_CREATE | IN_DELETE | IN_MOVED_TO);

	la_source_t *source = find_source_by_parent_wd(event->wd, event->name);
	if (!source)
		return;

	if (event->mask & IN_CREATE)
	{
		la_debug("handle_inotify_directory_event(%s)\n", source->name);
		watched_file_created(source);
	}
	else if (event->mask & IN_MOVED_TO)
	{
		la_debug("handle_inotify_directory_event(%s)\n", source->name);
		watched_file_moved_to(source);
	}
	else if (event->mask & IN_DELETE)
	{
		la_debug("handle_inotify_directory_event(%s)\n", source->name);
		watched_file_deleted(source);
	}

}


static void
handle_inotify_file_event(struct inotify_event *event)
{
	la_debug_inotify_event(event, IN_MODIFY);

	la_source_t *source = find_source_by_file_wd(event->wd);
	if (!source)
		/* as we're monitoring  directory, lots of file events for
		 * non-watched files will be triggered. So this is the "normal
		 * case" */
		return;

	la_debug("handle_inotify_file_event(%s)\n", source->name);
	handle_new_content(source);
}

static void
handle_inotify_event(struct inotify_event *event)
{

	if (event->len) /* only directory have a name (and thus a length) */
		handle_inotify_directory_event(event);
	else
		handle_inotify_file_event(event);

}

/*
 * Event loop for inotify mechanism
 */

void
watch_forever_inotify(void)
{
	char buffer[BUF_LEN];
	ssize_t num_read;
	struct inotify_event *event;

	for (;;)
	{
		num_read = read(inotify_fd, buffer, BUF_LEN);
		if (num_read == -1)
			die_err("Error reading from inotify");

		int i=0;
		while (i<num_read)
		{
			event = (struct inotify_event *) &buffer[i];
			handle_inotify_event(event);
			i += EVENT_SIZE + event->len;
		}
	}

}

/*
 * Add inotify watch for given filename. Also ads a watch for its parent dir if
 * dir is true.
 *
 * Returns la_watch_t
 */

void
watch_source_inotify(la_source_t *source)
{
	source->wd  = inotify_add_watch(inotify_fd, source->location, IN_MODIFY);
	if (source->wd  == -1)
		die_err("Can't add inotify watch for %s\n", source->location);

	if (!source->parent_wd) {
		/* all praise basename/dirname */
		char *tmp = strdup(source->location);
		source->parent_dir = strdup(dirname(tmp));
		free (tmp);

		source->parent_wd = inotify_add_watch(inotify_fd,
				source->parent_dir,
				IN_CREATE | IN_DELETE | IN_MOVED_TO);
		/* TODO: maybe this should not be a fatal error */
		if (source->parent_wd == -1)
			die_err("Can't add inotify watch for %s\n", source->parent_dir);
	}
}


void
init_watching_inotify(void)
{

	inotify_fd = inotify_init();
	if (inotify_fd == -1)
		die_hard("Can't initialize inotify");
}

#endif /* HAVE_INOTIFY */

/* vim: set autowrite expandtab: */