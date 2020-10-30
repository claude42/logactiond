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
#include <stdbool.h>

#ifdef WITH_LIBSODIUM
#include <sodium.h>
#endif /* WITH_LIBSODIUM */

#include "ndebug.h"
#include "logactiond.h"
#include "addresses.h"
#include "commands.h"
#include "configfile.h"
#include "crypto.h"
#include "endqueue.h"
#include "logging.h"
#include "messages.h"
#include "misc.h"

pthread_t remote_thread = 0;
static int client_fd4;
static int client_fd6;

/* TODO: check if current implementation really is thread safe */
/* TODO: maybe connect socket? */
/* TODO: fd mutex? */

void
send_message_to_single_address(const char *const message,
                const la_address_t *const remote_address)
{
        assert(la_config); assert_address(remote_address);
        la_debug("send_message_to_single_address(%s)", remote_address->text);
        if (!la_config->remote_enabled)
                return;

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
                        LOG_RETURN_ERRNO(, LOG_ERR, "Unable to create server socket");
        }

        const int message_sent = sendto(*fd_ptr, message, TOTAL_MSG_LEN, 0,
                        (struct sockaddr *) &remote_address->sa,
                        sizeof remote_address->sa);
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
send_add_entry_message(const la_command_t *const command, const la_address_t *const address)
{
        la_debug("send_add_entry_message()");
        assert(la_config); assert_command(command);

        if (!la_config->remote_enabled)
                return;

        /* TODO: would this make sense for commands w/o address as well? Then
         * maybe we should reflect this in the protocol and then implement
         * here... */
        if (!command->address)
                LOG_RETURN(, LOG_ERR, "Can't create message for command without "
                                "address");

        /* delibarately left out end_time and factor  here. Receiving end
         * should decide on duration. TODO: does that make sense? */
        char *const message = create_add_message(command->address->text,
                        command->rule_name, NULL, NULL);
        if (!message)
                LOG_RETURN(, LOG_ERR, "Unable to create message");
#ifdef WITH_LIBSODIUM
        if (la_config->remote_secret_changed)
        {
                generate_send_key_and_salt(la_config->remote_secret);
                la_config->remote_secret_changed = false;
        }
        if (!encrypt_message(message))
                LOG_RETURN(, LOG_ERR, "Unable to encrypt message");
#endif /* WITH_LIBSODIUM */

        if (address)
        {
                send_message_to_single_address(message, address);
        }
        else
        {
                assert_list(la_config->remote_send_to);
                for (la_address_t *remote_address =
                                ITERATE_ADDRESSES(la_config->remote_send_to);
                                (remote_address = NEXT_ADDRESS(remote_address));)
                {
                        send_message_to_single_address(message, remote_address);
                }
        }


        free(message);
}

/*
 * Cleanup when exiting.
 */

static void
cleanup_remote(void *const arg)
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
remote_loop(void *const ptr)
{
        la_debug("remote_loop()");

        const struct addrinfo *const ai = (struct addrinfo *) ptr;

        /* TODO: handover server_fd and ai (but ai only once) so cleanup can
         * close it */
        pthread_cleanup_push(cleanup_remote, NULL);

        const int server_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (server_fd == -1)
                die_err("Unable to create server socket");

        /* Set IPV6_V6ONLY to 1, otherwise it's not possible to bind to both
         * 0.0.0.0 and :: a the same time. Using only IPv6 would IMHO
         * complicate things (deal with IPv4 mapped addresses; feature not
         * available on some platforms). See
         * https://stackoverflow.com/questions/1618240/how-to-support-both-ipv4-and-ipv6-connections
         * for a discussion.
         */

        setsockopt(server_fd, IPPROTO_IPV6, IPV6_V6ONLY, &(int) { 1 }, sizeof (int));

        if (bind(server_fd, (struct sockaddr *) ai->ai_addr, ai->ai_addrlen) == -1)
                die_err("Unable to bind to server socket");

        for (;;)
        {
                if (shutdown_ongoing)
                {
                        la_debug("Shutting down remote thread.");
                        pthread_exit(NULL);
                }

                char buf[DEFAULT_LINEBUFFER_SIZE];
                struct sockaddr_storage remote_client;
                socklen_t remote_client_size = sizeof remote_client;
                const ssize_t num_read = recvfrom(server_fd, &buf,
                                DEFAULT_LINEBUFFER_SIZE, MSG_TRUNC,
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
                la_address_t *const from_addr = address_on_list_sa(
                                (struct sockaddr *) &remote_client,
                                la_config->remote_receive_from);

                if (!from_addr)
                {
                        char from[INET6_ADDRSTRLEN + 1];
                        const int r = getnameinfo((struct sockaddr *) &remote_client,
                                        sizeof remote_client, from, INET6_ADDRSTRLEN + 1,
                                        NULL, 0, NI_NUMERICHOST);
                        if (!r)
                                la_log(LOG_ERR, "Ignored message from %s - not on "
                                                "receive_from list!", from);
                        else
                                la_log(LOG_ERR, "Cannot determine remote host address: %s",
                                                gai_strerror(r));
                        continue;
                }

#ifdef WITH_LIBSODIUM
                if (!decrypt_message(buf, la_config->remote_secret, from_addr))
                        continue;
#endif /* WITH_LIBSODIUM */

                la_debug("Received message '%s' from %s",  buf, from_addr->text);

                parse_message_trigger_command(buf, from_addr->text);
                
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
        const char *node;
        if (la_config->remote_bind && !strcmp("*", la_config->remote_bind))
                node = NULL;
        else
                node = la_config->remote_bind;
        char port[6];
        snprintf(port, 6, "%d", la_config->remote_port);
        struct addrinfo *ai;
        int r = getaddrinfo(node, port, &hints, &ai); 
        if (r)
                die_err("Cannot get addrinfo: %s", gai_strerror(r));

        for (; ai; ai = ai->ai_next)
                xpthread_create(&remote_thread, NULL, remote_loop, ai, "remote");
}

/* 
 * start_routine for pthread_create called from sync_entries(). ptr points to a
 * string with the destination IP address.
 */

static void *
sync_all_entries(void *ptr)
{
        la_address_t address;
        if (!init_address_port(&address, (char *) ptr, la_config->remote_port))
        {
                la_log(LOG_ERR, "Cannot convert address in command %s!", (char *) ptr);
                free(ptr);
                return NULL;
        }

        free(ptr);

        xpthread_mutex_lock(&end_queue_mutex);

                const int queue_length = list_length(end_queue);
                char **message_array = (char **) xmalloc((queue_length + 1) *
                                sizeof (char *));
                int message_array_length = 0;

                for (la_command_t *command = ITERATE_COMMANDS(end_queue);
                                (command = NEXT_COMMAND(command));)
                {
                        if (!command->is_template && command->address)

                        {
                                assert(message_array_length < queue_length);
                                message_array[message_array_length++] =
                                        create_add_message(command->address->text,
                                                        command->rule_name, NULL,
                                                        NULL);
                        }
                }

        xpthread_mutex_unlock(&end_queue_mutex);

        for (int i = 0; i < message_array_length; i++)
        {
#ifdef WITH_LIBSODIUM
                if (la_config->remote_secret_changed)
                {
                        generate_send_key_and_salt(la_config->remote_secret);
                        la_config->remote_secret_changed = false;
                }
                if (!encrypt_message(message_array[i]))
                        LOG_RETURN(NULL, LOG_ERR, "Unable to encrypt message");
#endif /* WITH_LIBSODIUM */
                send_message_to_single_address(message_array[i], &address);
                free(message_array[i]);
                xnanosleep(0, 200000000);
        }

        free(message_array);

        return NULL;
}

void
sync_entries(const char *const buffer, const char *const from)
{
        assert(buffer);
        la_debug("sync_entries(%s)", buffer);

        char *const ptr = xstrdup(buffer[2] ? buffer+2 : from);
        //char *ptr = buffer[2] ? buffer+2 : from;

        pthread_t sync_entries_thread = 0;
        xpthread_create(&sync_entries_thread, NULL, sync_all_entries, ptr,
                        "sync");

}


/* vim: set autowrite expandtab: */
