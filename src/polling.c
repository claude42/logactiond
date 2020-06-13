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

#if !HAVE_INOTIFY

#include <syslog.h>
#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <time.h>

#include "ndebug.h"
#include "configfile.h"
#include "logging.h"
#include "misc.h"
#include "sources.h"
#include "watch.h"

static void
cleanup_watching_polling(void *const arg)
{
        la_debug("cleanup_watching_polling()");

        shutdown_watching();
}

static void
open_new_file(la_source_t *const source, const struct stat *const sb)
{
        source->file = freopen(source->location, "r",
                        source->file);
        if (source->file)
        {
                memcpy(&(source->stats), sb,
                                sizeof(struct stat));
        }
        else
        {
                la_log_errno(LOG_ERR, "Can't reopen source "
                                "\"%s\" - file \"%s\".",
                                source->source_group->name,
                                source->location);
                source->active = false;
        }
}

static void
open_file_again(la_source_t *source)
{
        source->file = fopen(source->location, "r");
        if (source->file)
        {
                source->active = true;
                /* Nice, but if fstat() fails, we still can't
                 * move forward */
                if (fstat(fileno(source->file), &(source->stats)) == -1)
                        unwatch_source(source);
        }
        else
        {
                la_vdebug("still inactive");
        }
}

static void
poll_source(la_source_t *source)
{
        struct stat sb;
        /* 1st case: file previously unaccessible
         * 
         * Try to open/stat, if it succeeds, great, go ahead
         * otherwise
         */
        if (!source->active)
        {
                open_file_again(source);
        }

        /* 2nd case: file has been accessible and still is, but
         * suddenly it's a different file
         * 
         * Great, try to open new file
         */
        else if (!stat(source->location, &sb) && (
                                sb.st_ino != source->stats.st_ino ||
                                sb.st_dev != source->stats.st_dev ||
                                sb.st_nlink == 0))
        {
                open_new_file(source, &sb);
        }

        /* 3rd case: file accessible, same as before
         *
         * Go and read new content, stop watching if that
         * should fail.
         */
        else if (!handle_new_content(source))
        {
                unwatch_source(source);
        }
}

/*
 * Event loop for poll mechanism
 */

static void *
watch_forever_polling(void *ptr)
{
        la_debug("watch_forever_polling()");
        assert(la_config); assert_list(la_config->source_groups);

        pthread_cleanup_push(cleanup_watching_polling, NULL);

        for (;;)
        {
                if (shutdown_ongoing)
                {
                        la_debug("Shutting down polling thread.");
                        pthread_exit(NULL);
                }

                xpthread_mutex_lock(&config_mutex);

                        for (la_source_group_t *source_group =
                                        ITERATE_SOURCE_GROUPS(la_config->source_groups);
                                        (source_group = NEXT_SOURCE_GROUP(source_group));)
                        {
                                for (la_source_t *source = ITERATE_SOURCES(source_group->sources);
                                                (source = NEXT_SOURCE(source));)
                                        poll_source(source);
                        }

                xpthread_mutex_unlock(&config_mutex);

                xnanosleep(2, 500000000);
        }

        assert(false);
        /* Will never be reached, simple here to make potential pthread macros
         * happy */
        pthread_cleanup_pop(1); // will never be reached
}

void
start_watching_polling_thread(void)
{
        la_debug("start_watching_polling_thread()");
        assert(!file_watch_thread);

        xpthread_create(&file_watch_thread, NULL,
                        watch_forever_polling, NULL, "polling");
}

#endif /* !HAVE_INOTIFY */

/* vim: set autowrite expandtab: */
