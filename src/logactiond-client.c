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
#include <err.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sodium.h>

#include "logactiond.h"

static int socket_fd;
static struct sockaddr_in server;


static void
print_usage(void)
{
        fprintf(stderr, "Usage: logactiond-queue add address rule [duration]\n"
                        "       logactiond-queue remove address\n");
}

static void
close_socket(void)
{
        if (close(socket_fd) == -1)
                err(1, "Unable to close socket");
}

static void
send_message(unsigned char *message)
{
        size_t message_sent = sendto(socket_fd, message, TOTAL_MSG_LEN, 0,
                        (struct sockaddr *) &server, sizeof(server));

        if (message_sent == -1)
        {
                close_socket();
                err(1, "Unable to send message");
        }
        else if (message_sent != TOTAL_MSG_LEN)
        {
                close_socket();
                err(1, "Sent truncated message");
        }
}


static void
setup_socket(void)
{
        /* BIG TODO: of course lift restriction to 127.0.0.1 */
        socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd == -1)
                err(1, "Unable to create server socket");

        server.sin_family = AF_INET;
        server.sin_port = htons(11111);
        /* TODO: huh? only one is necessary. Preference is inet_aton(), why is
         * inet_addr() still there?!? TODO */
        //server.sin_addr.s_addr = inet_addr("127.0.0.1");
        if (!inet_aton("127.0.0.1", &server.sin_addr))
        {
                close(socket_fd);
                err(1, "Unable to convert address");
        }
        memset(server.sin_zero, 0, sizeof(server.sin_zero));
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
                        /* TODO: error handling */
                        char *message = create_add_message(ip, rule, duration);
                        if (!message)
                                err(1, "Unable to create encrypted message");
                        setup_socket();
                        //send_message(message);
                        free(message);
                        close_socket();
                }
                else
                {
                        errx(1, "Wrong number of arguments.");
                }
        }
        else if (!strcmp(command, "remove"))
        {
                if (optind == argc-1)
                {
                        setup_socket();
                        char *message = create_remove_message(argv[optind]);
                        if (!message)
                                err(1, "Unable to create encrypted message");
                        //send_message(message);
                        free(message);
                        close_socket();
                }
                else
                {
                        errx(1, "Wrong number of arguments.");
                }
        }
        else
        {
                errx(1, "Unknown command \"%s\".", command);
        }

        exit(0);
}


/* vim: set autowrite expandtab: */

