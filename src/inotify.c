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

#if HAVE_INOTIFY

#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <assert.h>
#include <libgen.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <limits.h>
#include <stdnoreturn.h>

#include "ndebug.h"
#include "logactiond.h"
#include "configfile.h"
#include "inotify.h"
#include "logging.h"
#include "misc.h"
#include "sources.h"
#include "watch.h"

/* Buffer for reading inotify events */
#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define BUF_LEN (EVENT_SIZE + NAME_MAX + 1)

static int inotify_fd = 0;

static void
la_vdebug_inotify_event(const struct inotify_event *const event, const uint32_t monitored)
{
        assert(event);
        const char *str = NULL;

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
        else
                str = "unknown";

        if (event->mask & monitored)
                la_vdebug("%u: %s (%s)%s", event->wd, str, event->name, "");
        else
                la_vdebug("%u: %s (%s)%s", event->wd, str, event->name, " - ignored");
}

/*
 * Removes inotify watch for file and parent directory
 */

void
unwatch_source_inotify(la_source_t *const source)
{
        assert_source(source); assert(inotify_fd != 0);
        la_debug_func(source->location);

        /* Remove watch for file itself */
        if (inotify_rm_watch(inotify_fd, source->wd))
                la_log_errno(LOG_ERR, "Unable to unwatch source \"%s\".",
                                source->location);
        source->wd = 0;

        /* Remove watch for parent directory */
        if (source->parent_wd)
        {
                if (inotify_rm_watch(inotify_fd, source->parent_wd) &&
                                errno != EINVAL)
                        la_log_errno(LOG_ERR, "Unable to unwatch parent dir "
                                        "of source \"%s\"", source->location);
                source->parent_wd = 0;
        }
}


/*
 * Find existing la_source for a given wd (for the parent directory) and file
 * name.
 * NULL if no la_source exists yet
 */

static la_source_t *
find_source_by_parent_wd(const int parent_wd, const char *const file_name)
{
        assert(parent_wd); assert(file_name);
        assert(la_config);
        la_vdebug("find_source_by_parent_wd(%s)", file_name);

	/* Bail out if configuration is currently not available (e.g.
	 * during a reload*/
	if (!la_config->source_groups)
		return NULL;

        for (la_source_group_t *source_group = ITERATE_SOURCE_GROUPS(la_config->source_groups);
                        (source_group = NEXT_SOURCE_GROUP(source_group));)
        {
                for (la_source_t *source = ITERATE_SOURCES(source_group->sources);
                                (source = NEXT_SOURCE(source));)
                {
                        if (source->parent_wd == parent_wd &&
                                        !strendcmp(source->location, file_name))
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
find_source_by_file_wd(const int file_wd)
{
        assert(file_wd);
        assert(la_config);
        la_vdebug("find_source_by_file_wd(%u)", file_wd);

	/* Bail out if configuration is currently not available (e.g.
	 * during a reload*/
	if (!la_config->source_groups)
		return NULL;

        for (la_source_group_t *source_group = ITERATE_SOURCE_GROUPS(la_config->source_groups);
                        (source_group = NEXT_SOURCE_GROUP(source_group));)
        {
                for (la_source_t *source = ITERATE_SOURCES(source_group->sources);
                                (source = NEXT_SOURCE(source));)
                {
                        if (source->wd == file_wd)
                                return source;
                }
        }

        return NULL;
}

/*
 * Watched file has been recreated (after it had been previously deleted).
 * Start watching again.
 */

static void
watched_file_created(la_source_t *const source)
{
        assert_source(source);

        la_log(LOG_INFO, "Source \"%s\" - file \"%s\" has been re-created.",
                        source->source_group->name, source->location);

        /* unwatch not necessary in case of a previous IN_DELETE */
        if (source->file)
                unwatch_source(source);

        /* For reasons I don't understand, it sometimes (rather infrequently)
         * happens that an IN_CREATE event is fired but a subequent fopen() of
         * that very same file will fail. Maybe a simple (but kinda
         * embarassing) sleep() will help... */
        sleep(2);

        watch_source(source, SEEK_SET);
        if (!handle_new_content(source))
                la_log(LOG_ERR, "Reading from source \"%s\", file \"%s\" failed.",
                                source->source_group->name, source->location);
}

/*
 * Watched file has been moved away. Keep watching as there might be still some
 * events coming.
 */

static void
watched_file_moved_from(la_source_t *const source)
{
        assert_source(source);

        la_log(LOG_INFO, "Source \"%s\" - file \"%s\" has been moved away.",
                        source->source_group->name, source->location);

        /* Keep watching original file in case daemons are still logging
         * there. Switch only when new file is created. */
}

/*
 * A file has been moved to the watched location. Start watching.
 */

static void
watched_file_moved_to(la_source_t *const source)
{
        assert_source(source);

        la_log(LOG_INFO, "Source \"%s\" - file \"%s\" has been moved to watched "
                        "location.", source->source_group->name, source->location);

        /* unwatch not necessary in case of a previous IN_DELETE */
        if (source->file)
                unwatch_source(source);
        /* ignore existing content when fiel was moved here - better safe than
         * sorry */
        watch_source(source, SEEK_END);
}

/*
 * Watched file has been deleted - stop watching.
 */

static void
watched_file_deleted(la_source_t *const source)
{
        assert_source(source);

        la_log(LOG_INFO, "Source \"%s\" - file \"%s\" has been deleted.",
                        source->source_group->name, source->location);

        unwatch_source(source);
}


static void
handle_inotify_directory_event(const struct inotify_event *const event)
{
        la_vdebug_func(NULL);
        assert(event);
        la_vdebug_inotify_event(event, IN_CREATE | IN_DELETE | IN_MOVED_TO);

        la_source_t *source = find_source_by_parent_wd(event->wd, event->name);
        if (!source)
                return;

        if (event->mask & IN_CREATE)
        {
                la_debug_func(source->location);
                watched_file_created(source);
        }
        else if (event->mask & IN_MOVED_FROM)
        {
                la_debug_func(source->location);
                watched_file_moved_from(source);
        }
        else if (event->mask & IN_MOVED_TO)
        {
                la_debug_func(source->location);
                watched_file_moved_to(source);
        }
        else if (event->mask & IN_DELETE)
        {
                la_debug_func(source->location);
                watched_file_deleted(source);
        }

}


static void
handle_inotify_file_event(const struct inotify_event *const event)
{
        la_vdebug_func(NULL);
        assert(event);
        la_vdebug_inotify_event(event, IN_MODIFY);

        const la_source_t *const source = find_source_by_file_wd(event->wd);
        if (!source)
                /* as we're monitoring  directory, lots of file events for
                 * non-watched files will be triggered. So this is the "normal
                 * case" */
                return;

        la_vdebug_func(source->location);

        if (!handle_new_content(source))
                die_hard(true, "Reading from source \"%s\", file \"%s\" failed",
                                source->source_group->name, source->location);
}

static void
handle_inotify_event(const struct inotify_event *const event)
{
        assert(event);
        la_vdebug_func(NULL);

        xpthread_mutex_lock(&config_mutex);

                if (event->len) /* only directories have a name (and thus a length) */
                        handle_inotify_directory_event(event);
                else
                        handle_inotify_file_event(event);

        xpthread_mutex_unlock(&config_mutex);
}

static void
cleanup_watching_inotify(void *const arg)
{
        la_debug_func(NULL);

        shutdown_watching();

        if (close(inotify_fd) == -1)
                la_log_errno(LOG_ERR, "Can't close inotify fd!");
}

/*
 * Event loop for inotify mechanism
 */

noreturn static void *
watch_forever_inotify(void *const ptr)
{
        la_debug_func(NULL);

        pthread_cleanup_push(cleanup_watching_inotify, NULL);

        for (;;)
        {
                char buffer[BUF_LEN];
                const ssize_t num_read = read(inotify_fd, buffer, BUF_LEN);
                if (shutdown_ongoing)
                {
                        la_debug("Shutting down inotify thread.");
                        pthread_exit(NULL);
                }
                else if (num_read == -1)
                {
                        if (errno == EINTR)
                                la_debug("read interrupted!");
                        else
                                die_hard(true, "Error reading from inotify");
                }
                else
                {
                        struct inotify_event *event = NULL;
                        for (int i = 0; i <  num_read; i += EVENT_SIZE + event->len)
                        {
                                event = (struct inotify_event *) &buffer[i];
                                handle_inotify_event(event);
                        }
                }
        }

        assert(false);
        /* Will never be reached, simple here to make potential pthread macros
         * happy */
        pthread_cleanup_pop(1); // will never be reached
}

/*
 * Add inotify watch for given filename. Also ads a watch for its parent dir if
 * dir is true.
 *
 * Returns la_watch_t
 */

void
watch_source_inotify(la_source_t *const source)
{
        assert_source(source); assert(inotify_fd != 0);

        la_debug_func(source->location);

        source->wd  = inotify_add_watch(inotify_fd, source->location, IN_MODIFY);
        if (source->wd  == -1)
                die_hard(true, "Can't add inotify watch for %s", source->location);

        /* TODO can this really happen, i.e. source->wd == 0 but
         * source->parent_wd != 0 ? */
        if (!source->parent_wd)
        {
                /* all praise basename/dirname */
                char *const tmp = xstrdup(source->location);
                const char *const parent_dir = dirname(tmp);

                source->parent_wd = inotify_add_watch(inotify_fd,
                                parent_dir, IN_CREATE | IN_DELETE |
                                IN_MOVED_TO | IN_MOVED_FROM);
                /* TODO: maybe this should not be a fatal error */
                if (source->parent_wd == -1)
                        die_hard(true, "Can't add inotify watch for %s", parent_dir);
                free (tmp);
        }
}

void
init_watching_inotify(void)
{
        la_log(LOG_INFO, "Initializing inotify backend.");

        /* Calling inotify_init() twice will do funny stuff... */
        if (!inotify_fd)
        {
                inotify_fd = inotify_init();
                if (inotify_fd == -1)
                        die_hard(true, "Can't initialize inotify");
        }
        
}

void
start_watching_inotify_thread(void)
{
        la_debug_func(NULL);
        assert(!file_watch_thread);

        xpthread_create(&file_watch_thread, NULL,
                        watch_forever_inotify, NULL, "inotify");
}

#endif /* HAVE_INOTIFY */

/* vim: set autowrite expandtab: */
