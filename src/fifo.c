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

#include <pthread.h>
#include <syslog.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "logactiond.h"

pthread_t fifo_thread = 0;

static FILE *fifo;

static void
cleanup_fifo(void *arg)
{
        la_debug("cleanup_fifo()");

        if (fifo && fclose(fifo))
                la_log_errno(LOG_ERR, "Problem closing fifo");

        if (remove(FIFOFILE) == -1 && errno != ENOENT)
                la_log_errno(LOG_ERR, "Cannot remove fifo");
}

static void
create_fifo(void)
{
        la_debug("create_fifo()");

        if (remove(FIFOFILE) && errno != ENOENT)
                die_err("Cannot create fifo.");

        if (mkfifo(FIFOFILE, 0666) == -1)
                die_err("Cannot create fifo");

        fifo = fopen(FIFOFILE, "r+");
        if (!fifo)
                die_err("Cannot open fifo");
}

static void *
fifo_loop(void *ptr)
{
        la_debug("fifo_loop()");

        pthread_cleanup_push(cleanup_fifo, NULL);

        size_t buf_size = DEFAULT_LINEBUFFER_SIZE*sizeof(char);
        char *buf = alloca(buf_size);

        for (;;)
        {
                if (shutdown_ongoing)
                {
                        la_debug("Shutting down fifo thread.");
                        pthread_exit(NULL);
                }

                size_t num_read;
                if ((int) num_read == -1)
                {
                        if (feof(fifo))
                                continue;
                        else
                                die_err("Reading from fifo failed");
                }

                if (buf[num_read-1] == '\n')
                        buf[num_read-1] = '\0';

                la_debug("Received message '%s'", buf);

#if !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS)
                parse_message_trigger_command(buf, LA_FIFO);
#endif /* !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS) */
        }

        assert(false);
        /* Will never be reached, simply here to make potential pthread macros
         * happy */
        pthread_cleanup_pop(1);
}

/*
 * Start monitoring thread
 */

void
start_fifo_thread(void)
{
        la_debug("start_fifo_thread()");
        assert(!fifo_thread);

        create_fifo();

        xpthread_create(&fifo_thread, NULL, fifo_loop, NULL, "fifo");
}


/* vim: set autowrite expandtab: */
