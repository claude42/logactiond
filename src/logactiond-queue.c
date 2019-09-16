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

#include <getopt.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <stdio.h>


#include "logactiond.h"

static void
print_usage(void)
{
        fprintf(stderr, "Usage: logactiond-queue add address rule [duration]\n"
                        "       logactiond-queue remove address\n");
}


static void
command_add(char *ip, char *rule, char *duration)
{
        FILE *fifo = fopen(FIFOFILE, "a");
        if (!fifo)
                err(1, "Unable to open fifo");

        if (fprintf(fifo, "+%s,%s%s%s\n",
                        ip,
                        rule,
                        duration ? "," : "",
                        duration ? duration : "") < 0)
        {
                fclose(fifo);
                err(1, "Unable to write to fifo");
        }

        if (fclose(fifo) == EOF)
                err(1, "Unable to close fifo");
}

static void
command_remove(char *ip)
{
        FILE *fifo = fopen(FIFOFILE, "a");
        if (!fifo)
                err(1, "Unable to open fifo");

        if (fprintf(fifo, "-%s\n", ip) < 0)
        {
                fclose(fifo);
                err(1, "Unable to write to fifo");
        }

        if (fclose(fifo) == EOF)
                err(1, "Unable to close fifo");
}

int
main(int argc, char *argv[])
{
        for (;;)
        {
                static struct option long_options[] =
                {
                        {"debug",      optional_argument, NULL, 'd'},
                        {"verbose",    no_argument,       NULL, 'v'},
                        {0,            0,                 0,    0  }
                };

                int c = getopt_long(argc, argv, "c:d::v", long_options, NULL);

                if (c == -1)
                        break;
                
                switch (c)
                {
                        case 'v': 
                                break;
                        case '?':
                                print_usage();
                                exit(0);
                                break;
                        default:
                                printf("Getopt returnd character code %c\n", c);
                                break;
                }
        }

        if (optind >= argc)
                errx(1, "Wrong number of arguments.");

        char *command = argv[optind++];

        if (!strcmp(command, "add"))
        {
                if (optind == argc-2 || optind == argc-3)
                {
                        char *ip = argv[optind++];
                        char *rule = argv[optind++];
                        char *duration = NULL;
                        if (optind < argc)
                                duration = argv[optind];
                        command_add(ip, rule, duration);
                }
                else
                {
                        errx(1, "Wrong number of arguments.");
                }
        }
        else if (!strcmp(command, "remove"))
        {
                if (optind == argc-1)
                        command_remove(argv[optind]);
                else
                        errx(1, "Wrong number of arguments.");
        }
        else
        {
                errx(1, "Unknown command \"%s\".", command);
        }

        exit(0);
}


/* vim: set autowrite expandtab: */

