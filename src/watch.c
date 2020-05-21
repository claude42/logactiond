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

#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>

#include "ndebug.h"
#include "configfile.h"
#include "logging.h"
#include "misc.h"
#include "sources.h"
#include "watch.h"
#if HAVE_INOTIFY
#include "inotify.h"
#else /* HAVE_INOTIFY */
#include "polling.h"
#endif /* HAVE_INOTIFY */
#if HAVE_LIBSYSTEMD
#include "systemd.h"
#endif /* HAVE_LIBSYSTEMD */

pthread_t file_watch_thread = 0;


/*
 * Add general watch for given filename. Will not be called for systemd
 * sources.
 */

void
watch_source(la_source_t *source, const int whence)
{
        if (run_type == LA_UTIL_FOREGROUND)
                return;

        assert_source(source); assert(!source->file);
        la_debug("watch_source(%s)", source->location);

#ifndef NOWATCH
        source->file = fopen(source->location, "r");
        if (!source->file)
                die_err("Opening source \"%s\" failed", source->location);
        if (fstat(fileno(source->file), &(source->stats)) == -1)
                die_err("Stating source \"%s\" failed", source->location);
        if (fseek(source->file, 0, whence))
                die_err("Seeking in source \"%s\" failed", source->location);

        source->active = true;

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
        assert_source(source); assert(source->file); assert(source->active);
        la_debug("unwatch_source(%s)", source->location);

        if (run_type == LA_UTIL_FOREGROUND)
                return;

#ifndef NOWATCH

#if HAVE_INOTIFY
        unwatch_source_inotify(source);
#endif /* HAVE_INOTIFY */

        if (fclose(source->file))
                die_err("Closing source \"%s\" failed", source->location);
        source->file = NULL;
        source->active = false;

#endif /* NOWATCH */
}

/*
 * Do all steps necessary before files can be watched. Depending on the method
 * used, no such steps might be necessary at all.
 */

void
init_watching(void)
{
        la_debug("init_watching()");

#ifndef NOWATCH
        assert(la_config); assert_list(la_config->source_groups);
        if (!is_list_empty(la_config->source_groups))
        {
#if HAVE_INOTIFY
                init_watching_inotify();
#endif /* HAVE_INOTIFY */

                xpthread_mutex_lock(&config_mutex);
                        for (la_source_group_t *source_group = 
                                        ITERATE_SOURCE_GROUPS(la_config->source_groups);
                                        (source_group = NEXT_SOURCE_GROUP(source_group));)
                        {
                                for (la_source_t *source = ITERATE_SOURCES(
                                                        source_group->sources);
                                                (source = NEXT_SOURCE(source));)
                                {
                                        watch_source(source, SEEK_END);
                                }
                        }
                xpthread_mutex_unlock(&config_mutex);
        }

#if HAVE_LIBSYSTEMD
        if (la_config->systemd_source_group)
                init_watching_systemd();
#endif /* HAVE_LIBSYSTEMD */

#endif /* NOWATCH */
}

void
start_watching_threads(void)
{
        la_debug("start_watching_threads()");

        init_watching();

#ifndef NOWATCH
        assert(la_config); assert_list(la_config->source_groups);
        if (!is_list_empty(la_config->source_groups))
        {
#if HAVE_INOTIFY
                start_watching_inotify_thread();
#else /* HAVE_INOTIFY */
                start_watching_polling_thread();
#endif /* HAVE_INOTIFY */
        }

#if HAVE_LIBSYSTEMD
        if (la_config->systemd_source_group)
                start_watching_systemd_thread();
#endif /* HAVE_LIBSYSTEMD */

#endif /* NOWATCH */
}

/*
 * Shutdown everything related to watching.
 */

void
shutdown_watching(void)
{
        la_debug("shutdown_watching()");

#ifndef NOWATCH
        assert(la_config);

	/* Bail out if configuration is currently not available (e.g.
	 * during a reload*/
	if (!la_config->source_groups)
		return;

        if (!is_list_empty(la_config->source_groups))
        {
                xpthread_mutex_lock(&config_mutex);
                for (la_source_group_t *source_group = 
                                ITERATE_SOURCE_GROUPS(la_config->source_groups);
                                (source_group = NEXT_SOURCE_GROUP(source_group));)
                {
                        for (la_source_t *source = ITERATE_SOURCES(
                                                source_group->sources);
                                        (source = NEXT_SOURCE(source));)
                        {
                                unwatch_source(source);
                        }
                }
                xpthread_mutex_unlock(&config_mutex);
        }

#endif /* NOWATCH */
}


/* vim: set autowrite expandtab: */
