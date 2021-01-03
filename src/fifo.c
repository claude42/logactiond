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

#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#if HAVE_ALLOCA_H
#include <alloca.h>
#endif /* HAVE_ALLOCA_H */

#include "ndebug.h"
#include "logactiond.h"
#include "fifo.h"
#include "logging.h"
#include "messages.h"
#include "misc.h"

pthread_t fifo_thread = 0;

static FILE *fifo;

static void
cleanup_fifo(void *const arg)
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
                die_hard(true, "Cannot create fifo");

        if (mkfifo(FIFOFILE, 0666) == -1)
                die_hard(true, "Cannot create fifo");

        fifo = fopen(FIFOFILE, "r+");
        if (!fifo)
                die_hard(true, "Cannot open fifo");
}

static void *
fifo_loop(void *const ptr)
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

                const ssize_t num_read = getline(&buf, &buf_size, fifo);
                if  (num_read == -1  && !feof(fifo))
                {
                        die_hard(true, "Reading from fifo failed");
                }
                else if (num_read > 0)
                {
                        if (buf[num_read-1] == '\n')
                                buf[num_read-1] = '\0';

                        la_debug("Received message '%s'", buf);

#if !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS)
                        parse_message_trigger_command(buf, LA_FIFO);
#endif /* !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS) */
                }
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
