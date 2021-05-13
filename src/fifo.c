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
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#if HAVE_ALLOCA_H
#include <alloca.h>
#endif /* HAVE_ALLOCA_H */
#include <unistd.h>
#include <limits.h>
#include <stdnoreturn.h>

#include "ndebug.h"
#include "logactiond.h"
#include "fifo.h"
#include "logging.h"
#include "messages.h"
#include "misc.h"
#include "configfile.h"
#include "addresses.h"

pthread_t fifo_thread = 0;

static FILE *fifo = NULL;

la_address_t fifo_address =
{
        .text = "fifo",
        .domainname = NULL
};

static void
cleanup_fifo(void *const arg)
{
        la_debug_func(NULL);

        if (fifo && fclose(fifo))
                la_log_errno(LOG_ERR, "Problem closing fifo");

        assert(la_config);
        if (remove(la_config->fifo_path) == -1 && errno != ENOENT)
                la_log_errno(LOG_ERR, "Cannot remove fifo");

        fifo = NULL;

        fifo_thread = 0;
        wait_final_barrier();
        la_debug("Fifo thread exiting");
}

static void
create_fifo(void)
{
        la_debug_func(NULL);
        assert(la_config);

        if (remove(la_config->fifo_path) && errno != ENOENT)
                die_hard(true, "Cannot create fifo");

        if (la_config->fifo_mask)
                umask(la_config->fifo_mask);

        if (mkfifo(la_config->fifo_path, DEFFILEMODE) == -1)
                die_hard(true, "Cannot create fifo");

        if (la_config->fifo_user != UINT_MAX &&
                        chown(la_config->fifo_path, la_config->fifo_user,
                                la_config->fifo_group) == -1)
                die_hard(true, "Cannot set fifo owner/group");

        fifo = fopen(la_config->fifo_path, "r+");
        if (!fifo)
                die_hard(true, "Cannot open fifo");
}

noreturn static void *
fifo_loop(void *const ptr)
{
        la_debug_func(NULL);

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
                        parse_message_trigger_command(buf, &fifo_address);
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
        la_debug_func(NULL);
        assert(!fifo_thread);

        create_fifo();

        xpthread_create(&fifo_thread, NULL, fifo_loop, NULL, "fifo");
        thread_started();
        la_debug("Fifo thread startet (%i)", fifo_thread);
}


/* vim: set autowrite expandtab: */
