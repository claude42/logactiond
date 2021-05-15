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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>

#include "ndebug.h"
#include "logactiond.h"
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


/*
 * Add general watch for given filename. Will not be called for systemd
 * sources.
 */

void
watch_source(la_source_t *const source, const int whence)
{
        if (run_type == LA_UTIL_FOREGROUND)
                return;

        assert_source(source); assert(!source->file);
        la_debug_func(source->location);

#ifndef NOWATCH
        source->file = fopen(source->location, "r");
        if (!source->file)
                die_hard(true, "Opening source \"%s\" failed", source->location);
        if (fstat(fileno(source->file), &(source->stats)) == -1)
                die_hard(true, "Stating source \"%s\" failed", source->location);
        if (fseek(source->file, 0, whence))
                die_hard(true, "Seeking in source \"%s\" failed",
                                source->location);

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
unwatch_source(la_source_t *const source)
{
        assert_source(source); assert(source->file); assert(source->active);
        la_debug_func(source->location);

        if (run_type == LA_UTIL_FOREGROUND)
                return;

#ifndef NOWATCH

#if HAVE_INOTIFY
        unwatch_source_inotify(source);
#endif /* HAVE_INOTIFY */

        if (fclose(source->file))
                die_hard(true, "Closing source \"%s\" failed", source->location);
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
        la_debug_func(NULL);

#ifndef NOWATCH
        assert(la_config); assert_list(&la_config->source_groups);
        if (!is_list_empty(&la_config->source_groups))
        {
#if HAVE_INOTIFY
                init_watching_inotify();
#endif /* HAVE_INOTIFY */

                xpthread_mutex_lock(&config_mutex);
                        FOREACH(la_source_group_t, source_group,
                                        &la_config->source_groups)
                        {
                                FOREACH(la_source_t, source,
                                                &source_group->sources)
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
        la_debug_func(NULL);

        init_watching();

#ifndef NOWATCH
        assert(la_config); assert_list(&la_config->source_groups);
        if (!is_list_empty(&la_config->source_groups))
        {
#if HAVE_INOTIFY
                start_watching_inotify_thread();
#else /* HAVE_INOTIFY */
                start_watching_polling_thread();
#endif /* HAVE_INOTIFY */
        }

#if HAVE_LIBSYSTEMD
        if (la_config->systemd_source_group)
        {
                start_watching_systemd_thread();
        }
#endif /* HAVE_LIBSYSTEMD */

#endif /* NOWATCH */
}

/*
 * Shutdown everything related to watching.
 */

void
shutdown_watching(void)
{
        la_debug_func(NULL);

#ifndef NOWATCH
        assert(la_config);

        assert_list(&la_config->source_groups);
        if (!is_list_empty(&la_config->source_groups))
        {
                xpthread_mutex_lock(&config_mutex);
                FOREACH(la_source_group_t, source_group,
                                &la_config->source_groups)
                {
                        FOREACH(la_source_t, source, &source_group->sources)
                        {
                                unwatch_source(source);
                        }
                }
                xpthread_mutex_unlock(&config_mutex);
        }
#endif /* NOWATCH */
}


/* vim: set autowrite expandtab: */
