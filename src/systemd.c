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
#include <systemd/sd-journal.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>

#include <libconfig.h>

#include "logactiond.h"

pthread_t systemd_watch_thread = 0;
static sd_journal *journal = NULL;

static void
die_systemd(int systemd_errno, char *fmt, ...)
{
        va_list myargs;

        va_start(myargs, fmt);
        log_message(LOG_ERR, fmt, myargs, strerror(-systemd_errno));
        va_end(myargs);

        if (!shutdown_ongoing)
        {
                trigger_shutdown(EXIT_FAILURE, -systemd_errno);
                pthread_exit(NULL);
        }
        else
        {
                exit(EXIT_FAILURE);
        }
}

static void
cleanup_watching_systemd(void *arg)
{
        la_debug("cleanup_watching_systemd()");

        if (journal)
                sd_journal_close(journal);
}

static void *
watch_forever_systemd(void *ptr)
{
        la_debug("watch_forever_systemd()");
        assert(journal); assert(la_config->systemd_source);

        pthread_cleanup_push(cleanup_watching_systemd, NULL);

        int r; /* result from any of the sd_*() calls */

        for (;;)
        {
#define MESSAGE "MESSAGE"
#define MESSAGE_LEN 8
#define UNIT "_SYSTEMD_UNIT"
#define UNIT_LEN 14
                const void *data;
                const void *unit;
                size_t size;

                r = sd_journal_next(journal);
                if (r == 0)
                {
                        /* End of journal, wait for changes */

                        do
                        {
                                /* Only wait 1 second to make sure a shutdown
                                 * won't take too long */
                                r = sd_journal_wait(journal, 1000);
                        }
                        while (r == SD_JOURNAL_NOP && !shutdown_ongoing);

                        if (r >= 0 && !shutdown_ongoing)
                                continue; /* wait returned without error -
                                             rinse, repeat */
                }

                if (shutdown_ongoing)
                {
                        /* In case shutdown is ongoing, we don't care wether
                         * any of sd_journal_next() or sd_journal_wait()
                         * failed. We simply quit */
                        la_debug("Shutting down systemd thread.");
                        pthread_exit(NULL);
                }

                if (r < 0)
                {
                        /* r is either < 0 from sd_journal_next() or
                         * sd_journal_wait(). Die in either case */
                        die_systemd(r, "Accessing systemd journal failed");
                }

                /* When we reach this, no error occured, shutdown has not been
                 * initiated and there's something to read in the journal */

                r = sd_journal_get_data(journal, MESSAGE, &data, &size);
                if (r < 0)
                        die_systemd(r, "sd_journal_get_data() failed");

                r = sd_journal_get_data(journal, UNIT, &unit, &size);
                if (r < 0)
                        die_systemd(r, "sd_journal_get_data() failed");

                handle_log_line(la_config->systemd_source, data+MESSAGE_LEN,
                                unit+UNIT_LEN);
        }

        pthread_cleanup_pop(1); // will never be reached
}

static void
add_matches(void)
{
        la_debug("add_matches()");
        assert_source(la_config->systemd_source);
        assert(la_config->systemd_source->systemd_units);

        unsigned int len;
        char *match = NULL;

        sd_journal_flush_matches(journal);

        for (kw_node_t *unit = &(la_config->systemd_source->systemd_units)->head;
                        (unit = unit->succ->succ ? unit->succ : NULL);)
        {
                len = xstrlen("_SYSTEMD_UNIT=") + xstrlen(unit->name)+1;
                match = realloc(match, len);
                snprintf(match, len, "_SYSTEMD_UNIT=%s", unit->name);
                int r = sd_journal_add_match(journal, match, 0);
                if (r < 0)
                        die_systemd(r, "sd_journal_add_match() failed");
        }
        free(match);
}

void
init_watching_systemd(void)
{
        la_log(LOG_INFO, "Initializing systemd backend.");

        int r;

        if (!journal) {
                r = sd_journal_open(&journal, SD_JOURNAL_LOCAL_ONLY);
                if (r < 0)
                        die_systemd(r, "Opening systemd journal failed");
        }

        add_matches();

        r = sd_journal_seek_tail(journal);
        if (r < 0)
                die_systemd(r, "Seeking to end of systemd journal failed");

        /* Weird behavior of sd_journal_seek_tail() - which actually moves the
         * the last + 1 entry!. So one has to call sd_journal_previous() to
         * get the (at least by me) expected result.
         *
         * See also: https://bugs.freedesktop.org/show_bug.cgi?id=64614
         */
        sd_journal_previous(journal);

}

void
start_watching_systemd_thread(void)
{
        la_debug("start_watching_systemd_thread()");
        assert(!systemd_watch_thread);

        if (!systemd_watch_thread)
                xpthread_create(&systemd_watch_thread, NULL,
                                watch_forever_systemd, NULL);
}

#endif /* HAVE_LIBSYSTEMD */

/* vim: set autowrite expandtab: */
