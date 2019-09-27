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
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <syslog.h>
#include <netdb.h>
#include <stdbool.h>
#include <sodium.h>

#include "logactiond.h"

la_runtype_t run_type = LA_UTIL_FOREGROUND;
unsigned int log_level = LOG_DEBUG; /* by default log only stuff < log_level */
bool log_verbose = false;

static int socket_fd;
static struct addrinfo *ai;
static struct addrinfo hints;


static void
print_usage(void)
{
        fprintf(stderr, "Usage: logactiond-client password host add address rule [duration]\n"
                        "       logactiond-client password host remove address\n");
}

static void
cleanup(void)
{
        freeaddrinfo(ai);
        if (close(socket_fd) == -1)
                die_err("Unable to close socket");
}

static void
send_message(unsigned char *message)
{
        size_t message_sent = sendto(socket_fd, message, TOTAL_MSG_LEN, 0,
                        ai->ai_addr, ai->ai_addrlen);

        if (message_sent == -1)
        {
                cleanup();
                die_err("Unable to send message");
        }
        else if (message_sent != TOTAL_MSG_LEN)
        {
                cleanup();
                die_err("Sent truncated message");
        }
}


static void
setup_socket(char *host)
{
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        int r = getaddrinfo(host, "16473", &hints, &ai);
        if (r)
                die_hard("Unable to convert address: %s", gai_strerror(r));

        socket_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (socket_fd == -1)
        {
                freeaddrinfo(ai);
                die_err("Unable to create server socket");
        }
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

        if (optind > argc-3)
                die_hard("Wrong number of arguments.");

        char *password = argv[optind++];
        char *host = argv[optind++];
        char *command = argv[optind++];
        char *message = NULL;

        if (!strcmp(command, "add"))
        {
                if (optind == argc-2 || optind == argc-3)
                {
                        char *ip = argv[optind++];
                        char *rule = argv[optind++];
                        char *duration = NULL;
                        if (optind < argc)
                                duration = argv[optind];
                        message = create_add_message(ip, rule, duration);
                }
                else
                {
                        die_hard("Wrong number of arguments.");
                }
        }
        else if (!strcmp(command, "remove"))
        {
                if (optind == argc-1)
                        message = create_remove_message(argv[optind]);
                else
                        die_hard("Wrong number of arguments.");
        }
        else
        {
                die_hard("Unknown command \"%s\".", command);
        }

        if (!message)
                die_err("Unable to create message");
        if (!encrypt_message(message, password))
                die_err("Unable to encrypt message");

        setup_socket(host);
        send_message(message);
        free(message);
        cleanup();

        exit(0);
}


/* vim: set autowrite expandtab: */

