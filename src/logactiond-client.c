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
#include <netdb.h>

#include <sodium.h>

#include "logactiond.h"

static char *password = NULL;
static char *host = NULL;
static char *port = NULL;

static int socket_fd;
static struct addrinfo *ai;

static void
print_usage(void)
{
        fprintf(stderr,
                        "Usage: logactiond-client [-h host][-p password][-s port] "
                        "add address rule [end_time]\n"
                        "Usage: logactiond-client [-h host][-p password][-s port] "
                        "del address\n"
                        "Usage: logactiond-client [-h host][-p password][-s port] "
                        "flush\n"
                        "Usage: logactiond-client [-h host][-p password][-s port] "
                        "reload\n"
                        "Usage: logactiond-client [-h host][-p password][-s port] "
                        "shutdown\n"
                        "Usage: logactiond-client [-h host][-p password][-s port] "
                        "save\n");
}

static void
cleanup_socket(void)
{
        freeaddrinfo(ai);
        if (close(socket_fd) == -1)
                die_err("Unable to close socket");
}

static void
setup_socket(char *host)
{
        static struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));

        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        int r = getaddrinfo(host, port, &hints, &ai);
        if (r)
                die_hard("Unable to convert address: %s", gai_strerror(r));

        socket_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (socket_fd == -1)
        {
                freeaddrinfo(ai);
                die_err("Unable to create server socket");
        }
}

static void
send_remote_message(char *host, char *message)
{
        setup_socket(host);

        int message_sent = sendto(socket_fd, message, TOTAL_MSG_LEN, 0,
                        ai->ai_addr, ai->ai_addrlen);

        if (message_sent == -1)
        {
                cleanup_socket();
                die_err("Unable to send message");
        }
        else if (message_sent != TOTAL_MSG_LEN)
        {
                cleanup_socket();
                die_err("Sent truncated message");
        }

        cleanup_socket();
}

static void
send_local_message(char *message)
{
        FILE *fifo = fopen(FIFOFILE, "a");
        if (!fifo)
                die_err("Unable to open fifo");

        if (fprintf(fifo, "%s\n", message) < 0)
        {
                fclose(fifo);
                die_err("Unable to write to fifo");
        }

        if (fclose(fifo) == EOF)
                die_err("Unable to close fifo");
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
                        {"password",   required_argument, NULL, 'p'},
                        {"port",       required_argument, NULL, 's'},
                        {"host",       required_argument, NULL, 'h'},
                        {0,            0,                 0,    0  }
                };

                int c = getopt_long(argc, argv, "d::vp:h:s:", long_options, NULL);

                if (c == -1)
                        break;
                
                switch (c)
                {
                        case 'v': 
                                break;
                        case 'p':
                                password = optarg;
                                break;
                        case 'h':
                                host = optarg;
                                break;
                        case 's':
                                port = optarg;
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

        if (host && !password)
        {
                ssize_t passwd_size = 32;
                password = xgetpass("Password: ");
                if (!strlen(password))
                        die_hard("No password entered!");
        }

        if (host && !port)
                port = DEFAULT_PORT_STR;

        if (optind > argc-1)
                die_hard("Wrong number of arguments.");

        char *command = argv[optind++];
        char *message = NULL;

        if (!strcmp(command, "add"))
        {
                if (optind != argc-2 && optind != argc-3)
                        die_hard("Wrong number of arguments.");

                char *ip = argv[optind++];
                char *rule = argv[optind++];
                char *end_time = NULL;
                if (optind < argc)
                        end_time = argv[optind];
                message = create_add_message(ip, rule, end_time, NULL);
        }
        else if (!strcmp(command, "del"))
        {
                if (optind != argc-1)
                        die_hard("Wrong number of arguments.");

                message = create_del_message(argv[optind]);
        }
        else if (!strcmp(command, "flush"))
        {
                message = create_flush_message();
        }
        else if (!strcmp(command, "reload"))
        {
                message = create_reload_message();
        }
        else if (!strcmp(command, "shutdown"))
        {
                message = create_shutdown_message();
        }
        else if (!strcmp(command, "save"))
        {
                message = create_save_message();
        }
        else
        {
                die_hard("Unknown command \"%s\".", command);
        }

        if (!message)
                die_err("Unable to create message");

        if (host)
        {
                if (!encrypt_message(message, password))
                        die_err("Unable to encrypt message");
                send_remote_message(host, message);
        }
        else
        {
                send_local_message(message);
        }

        free(message);

        exit(0);
}


/* vim: set autowrite expandtab: */
