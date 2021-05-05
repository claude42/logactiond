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
#include <stdbool.h>
#include <assert.h>

#ifdef WITH_LIBSODIUM
#ifndef NOCRYPTO
#include <sodium.h>
#endif /* NOCRYPTO */
#endif /* WITH_LIBSODIUM */

#include "ndebug.h"
#include "crypto.h"
#include "fifo.h"
#include "logactiond.h"
#include "logging.h"
#include "messages.h"
#include "misc.h"
#include "nodelist.h"


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
                        "(no|v)?monitoring\n"
                        "Usage: ladc [-h host][-p password][-s port] "
                        "reset-counts\n"
                        "Usage: ladc [-h host][-p password][-s port] "
                        "save\n"
                        "Usage: ladc [-h host][-p password][-s port] "
                        "sync [host]\n"
                        "Usage: ladc [-h host][-p password][-s port] "
                        "stopsync\n"
                        "Usage: ladc [-h host][-p password][-s port] "
                        "dump\n"
                        "Usage: ladc [-h host][-p password][-s port] "
                        "(en|dis)able [rule]\n\n"
                        "Usage: ladc hosts\n"
                        "Usage: ladc rules\n"
                        "Usage: ladc diagnostics\n", stderr);
}

static void
cleanup_socket(void)
{
        freeaddrinfo(ai);
        if (close(socket_fd) == -1)
                die_hard(true, "Unable to close socket");
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
                die_hard(false, "Unable to convert address: %s.", gai_strerror(r));

        socket_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (socket_fd == -1)
        {
                freeaddrinfo(ai);
                die_hard(true, "Unable to create server socket");
        }
}

static bool
cat(const char *const filename)
{
        assert(filename);

        FILE *const stream = fopen(filename, "r");
        if (!stream)
                return false;

        bool result = false;
        size_t linebuffer_size = 0;
        char *linebuffer = NULL;

        while (getline(&linebuffer, &linebuffer_size, stream) != -1)
        {
                if (fputs(linebuffer, stdout) == EOF)
                        goto cleanup;
        }

        if (!feof(stream))
                goto cleanup;

        result = true;

cleanup:
        if (fclose(stream) == EOF)
                result = false;

        return result;
}

static bool
show_hosts(void)
{
        return cat(HOSTSFILE);
}

static bool
show_rules(void)
{
        return cat(RULESFILE);
}

static bool
show_diagnostics(void)
{
        return cat(DIAGFILE);
}

static void
send_remote_message(const char *message)
{
        ssize_t message_sent = sendto(socket_fd, message, TOTAL_MSG_LEN, 0,
                        ai->ai_addr, ai->ai_addrlen);

        cleanup_socket();

        if (message_sent == -1)
                die_hard(true, "Unable to send message");
        else if (message_sent != TOTAL_MSG_LEN)
                die_hard(true, "Sent truncated message");
        else
                return;
}

static void
send_local_message(char *message)
{
        const char *err_msg = NULL;
        bool print_strerror = true;
        FILE *fifo = fopen(FIFOFILE, "w");
        if (!fifo)
                die_hard(true, "Unable to open fifo");

        int fd = fileno(fifo);
        if (fd == -1)
        {
                err_msg = "Unable to get FD for fifo";
                goto cleanup;
        }

        struct stat stats;
        if (fstat(fd, &stats) == -1)
        {
                err_msg = "Unable to stat fifo";
                goto cleanup;
        }

        if (!S_ISFIFO(stats.st_mode))
        {
                err_msg = FIFOFILE " is not a fifo.";
                print_strerror = false;
                goto cleanup;
        }


        if (fprintf(fifo, "%s\n", message) < 0)
        {
                err_msg = "Unable to write to fifo";
                goto cleanup;
        }

        if (fclose(fifo) == EOF)
        {
                err_msg = "Unable to close fifo";
                fifo = NULL;
                goto cleanup;
        }
        fifo = NULL;
        
cleanup:
        if (fifo)
                fclose(fifo);

        if (err_msg)
                die_hard(print_strerror, err_msg);
}

int
main(int argc, char *argv[])
{
        const char *host = NULL;
        const char *password = NULL;
        const char *port = NULL;

        inject_misc_exit_function(die_hard);
        inject_nodelist_exit_function(die_hard);

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
                if (!password || password[0] == '\0')
                        die_hard(false, "No password entered!");
        }

        if (host && !port)
                port = DEFAULT_PORT_STR;

        if (optind > argc-1)
                die_hard(false, "Wrong number of arguments.");

        char *command = argv[optind++];
        bool success = false;
        char message[TOTAL_MSG_LEN] = "";
        bool (*postproc_function)(void) = NULL;

        if (!strcmp(command, "add"))
        {
                if (optind != argc-2 && optind != argc-3)
                        die_hard(false, "Wrong number of arguments.");

                char *ip = argv[optind++];
                char *rule = argv[optind++];
                char *end_time = NULL;
                if (optind < argc)
                        end_time = argv[optind];
                success = init_add_message(message, ip, rule, end_time, NULL);
        }
        else if (!strcmp(command, "del"))
        {
                if (optind != argc-1)
                        die_hard(false, "Wrong number of arguments.");

                success = init_del_message(message, argv[optind]);
        }
        else if (!strcmp(command, "flush"))
        {
                success = init_flush_message(message);
        }
        else if (!strcmp(command, "reload"))
        {
                success = init_reload_message(message);
        }
        else if (!strcmp(command, "shutdown"))
        {
                success = init_shutdown_message(message);
        }
        else if (!strcmp(command, "save"))
        {
                success = init_save_message(message);
        }
        else if (!strcmp(command, "debug"))
        {
                success = init_log_level_message(message, LOG_DEBUG+1);
        }
        else if (!strcmp(command, "vdebug"))
        {
                success = init_log_level_message(message, LOG_DEBUG+2);
        }
        else if (!strcmp(command, "nodebug"))
        {
                success = init_log_level_message(message, LOG_INFO+1);
        }
        else if (!strcmp(command, "monitoring"))
        {
                success = init_status_monitoring_message(message, 1);
        }
        else if (!strcmp(command, "vmonitoring"))
        {
                success = init_status_monitoring_message(message, 2);
        }
        else if (!strcmp(command, "nomonitoring"))
        {
                success = init_status_monitoring_message(message, 0);
        }
        else if (!strcmp(command, "reset-counts"))
        {
                success = init_reset_counts_message(message);
        }
        else if (!strcmp(command, "sync"))
        {
                if (optind == argc)
                        success = init_sync_message(message, NULL);
                else if (optind == argc-1)
                        success = init_sync_message(message, argv[optind++]);
                else
                        die_hard(false, "Wrong num ber of arguments.");
        }
        else if (!strcmp(command, "stopsync"))
        {
                success = init_stopsync_message(message);
        }
        else if (!strcmp(command, "dump"))
        {
                success = init_dump_message(message);
        }
        else if (!strcmp(command, "enable"))
        {
                if (optind != argc-1)
                        die_hard(false, "Wrong number of arguments.");

                success = init_enable_message(message, argv[optind]);
        }
        else if (!strcmp(command, "disable"))
        {
                if (optind != argc-1)
                        die_hard(false, "Wrong number of arguments.");

                success = init_disable_message(message, argv[optind]);
        }
        else if (!strcmp(command, "hosts"))
        {
                if (host)
                        die_hard(false, "Can only show hosts from local logactiond!");
                success = init_dump_message(message);
                postproc_function = show_hosts;
        }
        else if (!strcmp(command, "rules"))
        {
                if (host)
                        die_hard(false, "Can only show rules from local logactiond!");
                success = init_dump_message(message);
                postproc_function = show_rules;
        }
        else if (!strcmp(command, "diagnostics"))
        {
                if (host)
                        die_hard(false, "Can only show diagnostics from local logactiond!");
                success = init_dump_message(message);
                postproc_function = show_diagnostics;
        }
        else
        {
                die_hard(false, "Unknown command \"%s\".", command);
        }

        if (!success)
                die_hard(true, "Unable to execute command!");

        /* only send a message if one actually has been created */
        if (message[0])
        {
                if (host)
                {
#ifdef WITH_LIBSODIUM
                        generate_send_key_and_salt(password);
                        if (!encrypt_message(message))
                                die_hard(true, "Unable to encrypt message");
#endif /* WITH_LIBSODIUM */
                        setup_socket(host, port);
                        send_remote_message(message);
                }
                else
                {
                        send_local_message(message);
                }
        }

        sleep(1);

        if (postproc_function && !postproc_function())
                die_hard(true, "Unable to access information!");

        exit(0);
}


/* vim: set autowrite expandtab: */
