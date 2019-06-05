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

#include "logactiond.h"

static pthread_t watch_thread;

static void *watch_forever(void *ptr)
{
        la_debug("watch_forever()");
#if HAVE_INOTIFY
        watch_forever_inotify();
#else /* HAVE_INOTIFY */
        watch_forever_polling();
#endif /* HAVE_INOTIFY */
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
#if HAVE_INOTIFY
        init_watching_inotify();
#else /* HAVE_INOTIFY */
        init_watching_polling();
#endif /* HAVE_INOTIFY */

        xpthread_mutex_lock(&config_mutex);
        for (la_source_t *source = ITERATE_SOURCES(la_config->sources);
                        (source = NEXT_SOURCE(source));)
        {
                watch_source(source, SEEK_END);
        }
        xpthread_mutex_unlock(&config_mutex);

        xpthread_create(&watch_thread, NULL, watch_forever, NULL);
#endif /* NOWATCH */
}

/*
 * TODO
 */

void
shutdown_watching(void)
{
        la_debug("shutdown_watching()");

#ifndef NOWATCH
#if HAVE_INOTIFY
        shutdown_watching_inotify();
#else /* HAVE_INOTIFY */
        shutdown_watching_polling();
#endif /* HAVE_INOTIFY */
#endif /* NOWATCH */
}


/* vim: set autowrite expandtab: */
