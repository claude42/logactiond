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

#include <unistd.h>
#include <syslog.h>
#include <assert.h>
//#include <libgen.h>
#include <poll.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>

#include "logactiond.h"


/*
 * TODO
 */

void
unwatch_source_polling(la_source_t *source)
{
        assert_source(source);
        la_vdebug("unwatch_source_polling(%s)", source->name);

        // anything?
}

/*
 * Event loop for poll mechanism
 */

void
watch_forever_polling(void)
{
        la_debug("watch_forever_polling()");

        struct stat sb;


        for (;;)
        {
                if (shutdown_ongoing)
                {
                        la_debug("Shutting down polling thread.");
                        pthread_exit(NULL);
                }

                pthread_mutex_lock(&config_mutex);

                for (la_source_t *source = ITERATE_SOURCES(la_config->sources);
                                (source = NEXT_SOURCE(source));)
                {
                        la_vdebug("loop");
                        /* 1st case: file previously unaccessible
                         * 
                         * Try to open/stat, if it succeeds, great, go ahead
                         * otherwise
                         */
                        if (!source->active)
                        {
                                la_vdebug("not active");
                                source->file = fopen(source->location, "r");
                                if (source->file)
                                {
                                        la_vdebug("now active again");
                                        source->active = true;
                                        if (fstat(fileno(source->file), &(source->stats)) == -1)
                                        {
                                                la_vdebug("fstat failed, deactivating");
                                                unwatch_source(source);
                                        }
                                } else
                                        la_vdebug("still inactive");
                                continue;
                        }
                        la_vdebug("active");

                        /* 2nd case: file has been accessible and still is, but
                         * suddenly it's a different file
                         * 
                         * Great, try to open new file
                         */
                        if (!stat(source->location, &sb) && (
                                                sb.st_ino != source->stats.st_ino ||
                                                sb.st_dev != source->stats.st_dev ||
                                                sb.st_nlink == 0))
                        {
                                source->file = freopen(source->location, "r",
                                                source->file);
                                if (source->file)
                                        memcpy(&(source->stats), &sb,
                                                        sizeof(struct stat));
                                else
                                {
                                        la_log_errno(LOG_INFO, "Can't reopen");
                                        source->active = false;
                                }
                                continue;
                        }

                        /* 3rd case: file accessible, same as before
                         *
                         * Go and read new content
                         */
                        if (!handle_new_content(source))
                        {
                                la_vdebug("handling content failed");
                                unwatch_source(source);
                        }

                }

                pthread_mutex_unlock(&config_mutex);

                usleep(2500000);
        }
}

/*
 * TODO
 */

void
watch_source_polling(la_source_t *source)
{
        assert_source(source);
        la_debug("watch_source_polling(%s)", source->name);

        // anything?

}


void
init_watching_polling(void)
{
        la_debug("init_watching_polling()");

}

void
shutdown_watching_polling(void)
{
        la_debug("shutdown_watching_polling()");
        // currently not needed
}


/* vim: set autowrite expandtab: */
