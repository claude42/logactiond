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

#include <syslog.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "logactiond.h"
#include "nodelist.h"

pthread_t remote_thread = 0;
static int server_fd;
static int client_fd;
static struct sockaddr_in remote_server;


static void
send_message_to_single_address(char *message, la_address_t *remote_address)
{
        assert(la_config); assert_address(remote_address);
        la_debug("send_message_to_single_address()");

        if (client_fd == 0 || client_fd == -1)
        {
                client_fd = socket(AF_INET, SOCK_DGRAM, 0);
                if (client_fd == -1)
                {
                        la_log_errno(LOG_ERR, "Unable to create server socket");
                        return;
                }
        }

        remote_server.sin_family = remote_address->af;
        remote_server.sin_addr = remote_address->addr;
        remote_server.sin_port = htons(la_config->remote_port);
        memset(remote_server.sin_zero, 0, sizeof(remote_server.sin_zero));

        size_t message_sent = sendto(client_fd, message, strlen(message)+1, 0,
                        (struct sockaddr *) &remote_server,
                        sizeof(remote_server));
        if (message_sent == -1)
                la_log_errno(LOG_ERR, "Unable to send message to %s",
                                remote_address->text);
        else if (message_sent != strlen(message)+1)
                la_log_errno(LOG_ERR, "Sent truncated message to %s",
                                remote_address->text);
        else
                la_log(LOG_INFO, "Sent %s to %s", message,
                                remote_address->text);
}

void
send_add_entry_message(la_command_t *command)
{
        la_debug("send_add_entry_message()");
        assert(la_config);
        if (!la_config->remote_enabled)
                return;

        /* delibarately left out duration here. Receiving end should decide on
         * duration. TODO: does that make sense? */
        char message[100];
        if (!create_add_entry_message(message, 100, command, false))
        {
                la_log(LOG_ERR, "String overflow");
                return;
        }

        assert_list(la_config->remote_send_to);
        for (la_address_t *remote_address =
                        ITERATE_ADDRESSES(la_config->remote_send_to);
                        (remote_address = NEXT_ADDRESS(remote_address));)
        {
                send_message_to_single_address(message, remote_address);
        }
}

/*
 * Cleanup when exiting.
 */

static void
cleanup_remote(void *arg)
{
        la_debug("cleanup_remote()");
        if (server_fd > 0 && close(server_fd) == -1)
                die_err("Unable to close socket");
        if (client_fd > 0 && close(client_fd) == -1)
                die_err("Unable to close socket");
}

/*
 * Main loop
 */

static void *
remote_loop(void *ptr)
{
        la_debug("remote_loop()");

        pthread_cleanup_push(cleanup_remote, NULL);

        struct sockaddr_in server;
        struct sockaddr_storage remote_client;
        char buf[1024];

        server_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (server_fd == -1)
                die_err("Unable to create server socket");

        assert(la_config);
        if (xstrlen(la_config->remote_bind) == 0 ||
                        !strcmp("*", la_config->remote_bind))
        {
                server.sin_addr.s_addr = INADDR_ANY;
        }
        else
        {
                if (!inet_aton(la_config->remote_bind, &server.sin_addr))
                        die_err("Unable to convert IP address %s",
                                        la_config->remote_bind);
        }

        server.sin_family = AF_INET;
        server.sin_port = htons(la_config->remote_port);
        memset(server.sin_zero, 0, sizeof(server.sin_zero));

        if (bind(server_fd, (struct sockaddr *) &server, sizeof(server)) == -1)
                die_err("Unable to bind to server socket");

        for (;;)
        {
                if (shutdown_ongoing)
                {
                        la_debug("Shutting down remote thread.");
                        pthread_exit(NULL);
                }

                socklen_t remote_client_size = sizeof(remote_client);
                ssize_t n = recvfrom(server_fd, &buf, 1023, MSG_TRUNC,
                                (struct sockaddr *) &remote_client,
                                &remote_client_size);
                if (n == -1)
                        die_err("Error while receiving remote messages");
                buf[n] = '\0';
                la_log(LOG_INFO, "Received data: %s", buf);

                la_address_t *address;
                la_rule_t *rule;
                int duration;
                
#if !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS)
                if (remote_client.ss_family != AF_INET &&
                                remote_client.ss_family != AF_INET6)
                {
                        la_log(LOG_ERR, "Received message through unknown protocol?!");
                        free(address);
                        continue;
                }

                if (!parse_add_entry_message(buf, &address, &rule, &duration))
                        continue;

                char from[50];
                if (remote_client.ss_family == AF_INET)
                {
                        struct sockaddr_in *remote_client4 =
                                (struct sockaddr_in *) &remote_client;
                        inet_ntop(AF_INET, &(remote_client4->sin_addr), from, 50);
                }
                else if (remote_client.ss_family == AF_INET6)
                {
                        struct sockaddr_in6 *remote_client6 =
                                (struct sockaddr_in6 *) &remote_client;
                        inet_ntop(AF_INET6, &(remote_client6->sin6_addr), from, 50);
                }

                for (la_command_t *template =
                                ITERATE_COMMANDS(rule->begin_commands);
                                (template = NEXT_COMMAND(template));)
                        trigger_manual_command(address, template, duration,
                                        from);

                free(address);
#endif /* !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS) */
        }

        assert(false);
        /* Will never be reached, simply here to make potential pthread macros
         * happy */
        pthread_cleanup_pop(1);
}

/*
 * Start remote thread
 */

void
start_remote_thread(void)
{
        la_debug("start_remote_thread()");
        assert(la_config);
        if (!la_config->remote_enabled)
                return;
        assert(!remote_thread);

        xpthread_create(&remote_thread, NULL, remote_loop, NULL, "remote");
}


/* vim: set autowrite expandtab: */
