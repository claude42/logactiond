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
#include <netdb.h>
#include <stdio.h>
#include <errno.h>

#ifdef WITH_LIBSODIUM
#include <sodium.h>
#endif /* WITH_LIBSODIUM */

#include "logactiond.h"

pthread_t remote_thread = 0;
static int client_fd4;
static int client_fd6;

/* TODO: check if current implementation really is thread safe */
/* TODO: maybe connect socket? */

static void
send_message_to_single_address(char *message, la_address_t *remote_address)
{
        assert(la_config); assert_address(remote_address);
        la_debug("send_message_to_single_address()");

        /* Test for shutdown first, just to make sure nobody has closed the fds
         * already */
        if (shutdown_ongoing)
                return;

        /* Select correct file descriptor, open new socket if not already done
         * so */
        int *fd_ptr = remote_address->sa.ss_family == AF_INET ? &client_fd4 : &client_fd6;
        if ((*fd_ptr == 0 || *fd_ptr == -1))
        {
                *fd_ptr = socket(remote_address->sa.ss_family, SOCK_DGRAM, 0);
                if (*fd_ptr == -1)
                {
                        la_log_errno(LOG_ERR, "Unable to create server socket");
                        return;
                }
        }

        int message_sent = sendto(*fd_ptr, message, TOTAL_MSG_LEN, 0,
                        (struct sockaddr *) &remote_address->sa,
                        sizeof(remote_address->sa));
        if (message_sent == -1)
                la_log_errno(LOG_ERR, "Unable to send message to %s",
                                remote_address->text);
        else if (message_sent != TOTAL_MSG_LEN)
                la_log_errno(LOG_ERR, "Sent truncated message to %s",
                                remote_address->text);
}

/*
 * Currently only called from trigger_command()
 */
void
send_add_entry_message(la_command_t *command)
{
        la_debug("send_add_entry_message()");
        assert(la_config); assert_command(command);

        if (!la_config->remote_enabled)
                return;

        /* TODO: would this make sense for commands w/o address as well? Then
         * maybe we should reflect this in the protocol and then implement
         * here... */
        if (!command->address)
        {
                la_log(LOG_ERR, "Can't create message for command without "
                                "address");
                return;
        }

        /* delibarately left out end_time and factor  here. Receiving end
         * should decide on duration. TODO: does that make sense? */
        char *message;
        if (!(message = create_add_message(command->address->text,
                                command->rule_name, NULL, NULL)))
        {
                la_log(LOG_ERR, "Unable to create message");
                return;
        }
#ifdef WITH_LIBSODIUM
        if (!encrypt_message(message, la_config->remote_secret))
        {
                la_log(LOG_ERR, "Unable to encrypt message");
                return;
        }
#endif /* WITH_LIBSODIUM */

        assert_list(la_config->remote_send_to);
        for (la_address_t *remote_address =
                        ITERATE_ADDRESSES(la_config->remote_send_to);
                        (remote_address = NEXT_ADDRESS(remote_address));)
        {
                send_message_to_single_address(message, remote_address);
        }

        free(message);
}

/*
 * Cleanup when exiting.
 */

static void
cleanup_remote(void *arg)
{
        la_debug("cleanup_remote()");
        /* TODO: re-enable mt save */
        /*if (server_fd > 0 && close(server_fd) == -1)
                die_err("Unable to close socket");*/
        if (client_fd4 > 0 && close(client_fd4) == -1)
                die_err("Unable to close socket");
        if (client_fd6 > 0 && close(client_fd6) == -1)
                die_err("Unable to close socket");
}



/*
 * Main loop
 */

static void *
remote_loop(void *ptr)
{
        la_debug("remote_loop()");

        int server_fd;
        struct addrinfo *ai = (struct addrinfo *) ptr;
        struct sockaddr_storage remote_client;
        char buf[DEFAULT_LINEBUFFER_SIZE];

        /* TODO: handover server_fd and ai (but ai only once) so cleanup can
         * close it */
        pthread_cleanup_push(cleanup_remote, NULL);

        server_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (server_fd == -1)
                die_err("Unable to create server socket");

        /* Set IPV6_V6ONLY to 1, otherwise it's not possible to bind to both
         * 0.0.0.0 and :: a the same time. Using only IPv6 would IMHO
         * complicate things (deal with IPv4 mapped addresses; feature not
         * available on some platforms). See
         * https://stackoverflow.com/questions/1618240/how-to-support-both-ipv4-and-ipv6-connections
         * for a discussion.
         */

        int yes = 1;
        setsockopt(server_fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *) &yes,
                        sizeof yes);

        if (bind(server_fd, (struct sockaddr *) ai->ai_addr, ai->ai_addrlen) == -1)
                die_err("Unable to bind to server socket");

        for (;;)
        {
                if (shutdown_ongoing)
                {
                        la_debug("Shutting down remote thread.");
                        pthread_exit(NULL);
                }

                socklen_t remote_client_size = sizeof(remote_client);
                ssize_t num_read = recvfrom(server_fd, &buf, 1023, MSG_TRUNC,
                                (struct sockaddr *) &remote_client,
                                &remote_client_size);
                if (num_read == -1)
                {
                        if (errno == EINTR)
                                continue;
                        else
                                die_err("Error while receiving remote messages");
                }

                buf[num_read] = '\0';

#if !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS)
                char from[INET6_ADDRSTRLEN];
                int r = getnameinfo((struct sockaddr *) &remote_client,
                                sizeof remote_client, from, INET6_ADDRSTRLEN,
                                NULL, 0, NI_NUMERICHOST);
                if (r)
                {
                        la_log(LOG_ERR, "Cannot determine remote host address: %s",
                                        gai_strerror(r));
                        continue;
                }

                la_address_t *from_addr = address_on_list_sa(
                                (struct sockaddr *) &remote_client,
                                sizeof remote_client,
                                la_config->remote_receive_from);

                if (!from_addr)
                {
                        la_log(LOG_ERR, "Ignored message from %s - not on "
                                        "receive_from list!", from);
                        continue;
                }

#ifdef WITH_LIBSODIUM
                if (!decrypt_message(buf, la_config->remote_secret, from_addr))
                        continue;
#endif /* WITH_LIBSODIUM */

                la_debug("Received message '%s' from %s",  buf, from);

                parse_message_trigger_command(buf, from);
                
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
        if (!la_config->remote_enabled || remote_thread)
                return;

        struct addrinfo hints;
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_flags = AI_PASSIVE | AI_V4MAPPED | AI_ADDRCONFIG;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;

        assert(la_config);
        char *node;
        if (la_config->remote_bind && !strcmp("*", la_config->remote_bind))
                node = NULL;
        else
                node = la_config->remote_bind;
        char port[6];
        snprintf(port, 6, "%u", la_config->remote_port);
        struct addrinfo *ai;
        int r = getaddrinfo(node, port, &hints, &ai); 
        if (r)
                die_err("Cannot get addrinfo: %s", gai_strerror(r));

        for (; ai; ai = ai->ai_next)
                xpthread_create(&remote_thread, NULL, remote_loop, ai, "remote");
}


/* vim: set autowrite expandtab: */
