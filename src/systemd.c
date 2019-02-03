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

#if HAVE_LIBSYSTEMD

#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <syslog.h>
#include <assert.h>
#include <syslog.h>
#include <libgen.h>
#include <systemd/sd-journal.h>

#include <libconfig.h>

#include "logactiond.h"

/* Buffer for reading inotify events */
#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

static sd_journal *j;
static la_source_t *systemd_source = NULL;

/*
 * Removes inotify watch for file but not for parent directory
 */

void
unwatch_source_systemd(la_source_t *source)
{
        assert_source(source);

	la_debug("unwatch_source_systemd(%s)\n", source->name);

        // TODO
}


/*
 * Event loop for inotify mechanism
 */

void
watch_forever_systemd(void)
{
        la_debug("watch_forever_systemd()\n");

        int r;

        for (;;)
        {
                const void *data;
                size_t size;

                /* TODO: error handling, printout r */
                r = sd_journal_next(j);
                if (r<0)
                {
                        die_err("sd_journal_next() failed.\n");
                }
                else if (r == 0)
                {
                        /* End of journal, wait for changes */
                        r = sd_journal_wait(j, (uint64_t) -1);
                        if (r<0)
                                die_err("sd_journal_wait() failed.\n");
                        continue;
                }
                r = sd_journal_get_data(j, "MESSAGE", &data, &size);
                if (r < 0)
                {
                        die_err("sd_journal_get_data() failed.\n");
                }
                handle_log_line(systemd_source, data);
        }
}

/*
 * Open journal (and what else?!)
 */

void
watch_source_systemd(la_source_t *source)
{
        assert_source(source);

        la_debug("watch_source_systemd(%s)\n", source->name);

        if (systemd_source)
                die_semantic("More than one source using systemd backend!\n");
        systemd_source = source;

        if (!sd_journal_open(&j, 0))
                die_err("Opening systemd journal failed!\n");

        /* TODO: error handling */
        sd_journal_seek_tail(j);
}


void
init_watching_systemd(void)
{
        la_debug("init_watching_systemd()\n");

        /* something to do here?! */
}

#endif /* HAVE_LIBSYSTEMD */

/* vim: set autowrite expandtab: */
