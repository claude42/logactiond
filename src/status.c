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

#include <time.h>
#include <pthread.h>
//#include <stdlib.h>
//#include <unistd.h>
//#include <syslog.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
//#include <arpa/inet.h>

//#include <libconfig.h>

#include "logactiond.h"
#include "nodelist.h"

/*
 * Dumps a summary of a list of commands (usually the end queue) to a file.
 *
 * NOTE: must be called with end_queue_mutex locked when called for the end
 * queue.
 */

void
dump_queue_status(kw_list_t *queue)
{
        if (!output_status)
                return;

        FILE *status_file = fopen(STATUSFILE, "w");
        if (!status_file)
                die_hard("Can't create \" STATUSFILE \"!");

        fprintf(status_file, "IP address                                         "
                        "Time     Rule       Action\n"
                        "============================================="
                        "=========================================\n");

        /* INET6_ADDRSTRLEN 46 + "/123*/

        for (la_command_t *command = ITERATE_COMMANDS(queue);
                        (command = NEXT_COMMAND(command));)
        {
                assert_command(command);
                /* not interested in shutdown commands */
                if (command->end_time == INT_MAX)
                        break;
                la_debug("printing %s", command->name);

                char *adr = command->address ? command->address->text : "-";

                char end_time[9];
                strftime(end_time, 8, "%T", localtime(&(command->end_time)));

                fprintf(status_file,
                                "%-50.50s %-8.8s %-10.10s %-15.15s\n",
                                adr, end_time, command->name,
                                command->rule->name);
        }
        if (fclose(status_file))
                die_hard("Can't close \" STATUSFILE \"!");
}

/* vim: set autowrite expandtab: */
