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

#if HAVE_LIBSYSTEMD

#include <stdlib.h>
#include <systemd/sd-journal.h>
#include <pthread.h>
#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdnoreturn.h>

#include "ndebug.h"
#include "logactiond.h"
#include "configfile.h"
#include "logging.h"
#include "misc.h"
#include "sources.h"
#include "systemd.h"

// _LEN includes terminal '\0'

#define MESSAGE "MESSAGE"
#define MESSAGE_LEN 8
#define UNIT "_SYSTEMD_UNIT"
#define UNIT_LEN 14


pthread_t systemd_watch_thread = 0;
static sd_journal *journal = NULL;
static char *unit_buffer = NULL;

static void
die_systemd(const int systemd_errno, const char *const fmt, ...)
{
        va_list myargs;

        assert(fmt);
        va_start(myargs, fmt);
        log_message_va_list(LOG_ERR, fmt, myargs, strerror(-systemd_errno));
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
cleanup_watching_systemd(void *const arg)
{
        la_debug_func(NULL);

        free(unit_buffer);

        if (journal)
                sd_journal_close(journal);
}

noreturn static void *
watch_forever_systemd(void *const ptr)
{
        static int unit_buffer_length = DEFAULT_LINEBUFFER_SIZE;
        unit_buffer = xmalloc(unit_buffer_length);

        la_debug_func(NULL);
        assert(journal); assert(la_config->systemd_source_group);

        pthread_cleanup_push(cleanup_watching_systemd, NULL);

        for (;;)
        {
                const void *data;
                size_t size;
                int r; /* result from any of the sd_*() calls */

                r = sd_journal_next(journal);
                if (r == 0)
                {
                        /* End of journal, wait for changes */

                        do
                        {
                                r = sd_journal_wait(journal, (uint64_t) -1);
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

                /* First get the name of the systemd unit */
                r = sd_journal_get_data(journal, UNIT, &data, &size);
                if (r < 0)
                        die_systemd(r, "sd_journal_get_data() failed");

                if ((int) size+1 > unit_buffer_length)
                {
                        unit_buffer = xrealloc(unit_buffer, size+1);
                        unit_buffer_length = size+1;
                }
                memcpy(unit_buffer, (char *)data+UNIT_LEN, size-UNIT_LEN);
                unit_buffer[size-UNIT_LEN] = '\0';

                /* Second get rest of the log line */
                r = sd_journal_get_data(journal, MESSAGE, &data, &size);
                if (r < 0)
                        die_systemd(r, "sd_journal_get_data() failed");

                la_vdebug("Unit: %s, line: %s", unit_buffer, (char *)data+MESSAGE_LEN);

                xpthread_mutex_lock(&config_mutex);
                        const clock_t c = clock();
                        handle_log_line(SYSTEMD_SOURCE,
                                        (char *) data+MESSAGE_LEN, unit_buffer);
                        la_config->total_clocks += clock() - c;
                        la_config->invocation_count++;
                xpthread_mutex_unlock(&config_mutex);
        }

        assert(false);
        /* Will never be reached, simple here to make potential pthread macros
         * happy */
        pthread_cleanup_pop(1);
}

static void
add_matches(void)
{
        la_debug_func(NULL);
        assert(la_config);
        assert(la_config->systemd_source_group);
        assert_list(la_config->systemd_source_group->systemd_units);

        char *match = NULL;

        sd_journal_flush_matches(journal);

        for (kw_node_t *unit = &(la_config->systemd_source_group->systemd_units)->head;
                        (unit = unit->succ->succ ? unit->succ : NULL);)
        {
                // space for "_SYSTEMD_UNIT=" + unit->name + '\0'
                const int len = UNIT_LEN + 1 + xstrlen(unit->name);
                match = xrealloc(match, len);
                snprintf(match, len, UNIT "=%s", unit->name);
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
        if (r < 0)
                die_systemd(r, "Seeking to end of systemd journal failed");
}

void
start_watching_systemd_thread(void)
{
        la_debug_func(NULL);
        assert(!systemd_watch_thread);

        xpthread_create(&systemd_watch_thread, NULL,
                        watch_forever_systemd, NULL, "systemd");
}

#endif /* HAVE_LIBSYSTEMD */

/* vim: set autowrite expandtab: */
