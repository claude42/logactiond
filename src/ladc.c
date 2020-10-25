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

#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <syslog.h>

#ifdef WITH_LIBSODIUM
#include <sodium.h>
#endif /* WITH_LIBSODIUM */

#include "ndebug.h"
#include "crypto.h"
#include "fifo.h"
#include "logactiond.h"
#include "logging.h"
#include "messages.h"
#include "misc.h"


static int socket_fd;
static struct addrinfo *ai;

static void
print_usage(void)
{
        fputs("Usage: ladc [-h host][-p password][-s port] "
                        "add address rule [end_time]\n"
                        "Usage: ladc [-h host][-p password][-s port] "
                        "del address\n"
                        "Usage: ladc [-h host][-p password][-s port] "
                        "flush\n"
                        "Usage: ladc [-h host][-p password][-s port] "
                        "reload\n"
                        "Usage: ladc [-h host][-p password][-s port] "
                        "shutdown\n"
                        "Usage: ladc [-h host][-p password][-s port] "
                        "(no|v)?debug\n"
                        "Usage: ladc [-h host][-p password][-s port] "
                        "reset-counts\n"
                        "Usage: ladc [-h host][-p password][-s port] "
                        "save\n"
                        "Usage: ladc [-h host][-p password][-s port] "
                        "sync [host]\n"
                        "Usage: ladc [-h host][-p password][-s port] "
                        "dump\n"
                        "Usage: ladc [-h host][-p password][-s port] "
                        "(en|dis)able \n", stderr);
}

static void
cleanup_socket(void)
{
        freeaddrinfo(ai);
        if (close(socket_fd) == -1)
                die_err("Unable to close socket");
}

static void
setup_socket(const char *host, const char *port)
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
send_remote_message(const char *message)
{
        int message_sent = sendto(socket_fd, message, TOTAL_MSG_LEN, 0,
                        ai->ai_addr, ai->ai_addrlen);

        cleanup_socket();

        if (message_sent == -1)
                die_err("Unable to send message");
        else if (message_sent != TOTAL_MSG_LEN)
                die_err("Sent truncated message");
        else
                return;
}

static void
send_local_message(char *message)
{
        FILE *fifo = fopen(FIFOFILE, "w");
        if (!fifo)
                die_err("Unable to open fifo");

        int fd = fileno(fifo);
        if (fd == -1)
        {
                fclose(fifo);
                die_hard("Unable to get FD for fifo");
        }

        struct stat stats;
        if (fstat(fd, &stats) == -1)
        {
                fclose(fifo);
                die_err("Unable to stat fifo");
        }

        if (!S_ISFIFO(stats.st_mode))
        {
                fclose(fifo);
                die_hard(FIFOFILE " is not a fifo");
        }


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
        const char *host = NULL;
        const char *password = NULL;
        const char *port = NULL;

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
        else if (!strcmp(command, "debug"))
        {
                message = create_log_level_message(LOG_DEBUG+1);
        }
        else if (!strcmp(command, "vdebug"))
        {
                message = create_log_level_message(LOG_DEBUG+2);
        }
        else if (!strcmp(command, "nodebug"))
        {
                message = create_log_level_message(LOG_INFO+1);
        }
        else if (!strcmp(command, "reset-counts"))
        {
                message = create_reset_counts_message();
        }
        else if (!strcmp(command, "sync"))
        {
                if (optind == argc)
                        message = create_sync_message(NULL);
                else if (optind == argc-1)
                        message = create_sync_message(argv[optind++]);
                else
                        die_hard("Wrong num ber of arguments.");
        }
        else if (!strcmp(command, "dump"))
        {
                message = create_dump_message();
        }
        else if (!strcmp(command, "enable"))
        {
                if (optind != argc-1)
                        die_hard("Wrong number of arguments.");

                message = create_enable_message(argv[optind]);
        }
        else if (!strcmp(command, "disable"))
        {
                if (optind != argc-1)
                        die_hard("Wrong number of arguments.");

                message = create_disable_message(argv[optind]);
        }
        else
        {
                die_hard("Unknown command \"%s\".", command);
        }

        if (!message)
                die_err("Unable to create message");

        if (host)
        {
#ifdef WITH_LIBSODIUM
                generate_send_key_and_salt(password);
                if (!encrypt_message(message))
                        die_err("Unable to encrypt message");
#endif /* WITH_LIBSODIUM */
                setup_socket(host, port);
                send_remote_message(message);
        }
        else
        {
                send_local_message(message);
        }

        free(message);

        exit(0);
}


/* vim: set autowrite expandtab: */
