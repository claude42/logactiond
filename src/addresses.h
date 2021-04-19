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

#ifndef __addresses_h
#define __addresses_h

#include <config.h>

#include <netinet/in.h>
#include <regex.h>
#include <stdbool.h>
#ifdef WITH_LIBSODIUM
#ifndef NOCRYPTO
#include <sodium.h>
#endif /* NOCRYPTO */
#endif /* WITH_LIBSODIUM */

#include "ndebug.h"
#include "nodelist.h"

/* Max length of an IPv6 address + 4 bytes for /prefix */
#define MAX_ADDR_TEXT_SIZE INET6_ADDRSTRLEN + 4

#define ITERATE_ADDRESSES(ADDRESSES) (la_address_t *) &(ADDRESSES)->head
#define NEXT_ADDRESS(ADDRESS) (la_address_t *) (ADDRESS->node.succ->succ ? ADDRESS->node.succ : NULL)
#define HAS_NEXT_ADDRESS(ADDRESS) ADDRESS->node.succ
#define REM_ADDRESSES_HEAD(ADDRESSES) (la_address_t *) rem_head(ADDRESSES)

#ifdef NDEBUG
#define assert_address(ADDRESS) (void)(0)
#else /* NDEBUG */
#define assert_address(ADDRESS) assert_address_ffl(ADDRESS, __func__, __FILE__, __LINE__)
#endif /* NDEBUG */

#define ADDRESS_NAME(ADDRESS) (ADDRESS->domainname ? ADDRESS->domainname : ADDRESS->text)

#define free_address_list(list) \
        free_list(list, (void (*)(void *const)) free_address)

typedef struct la_address_s
{
        kw_node_t node;
        struct sockaddr_storage sa;
        socklen_t salen;
        int prefix;
        char text[MAX_ADDR_TEXT_SIZE + 1];
        char *domainname;

        /* only used for hosts that we receive messages from */
#ifndef NOCRYPTO
#ifdef WITH_LIBSODIUM
        unsigned char *key;
        unsigned char *salt;
#endif /* WITH_LIBSODIUM */
#endif /* NOCRYPTO */
} la_address_t;

void assert_address_ffl(const la_address_t *address, const char *func,
                const char *file, int line);

bool query_domainname(la_address_t *address);

int get_port(const la_address_t *address);

void set_port(la_address_t *address, int port);

const char *get_ip_version(const la_address_t *address);

int adrcmp(const la_address_t *a1, const la_address_t *a2);

la_address_t *address_on_list(const la_address_t *address, const kw_list_t *list);

la_address_t *address_on_list_sa(const struct sockaddr *sa, const kw_list_t *list);

la_address_t *address_on_list_str(const char *host, const kw_list_t *list);

bool init_address_port(la_address_t *addr, const char *ip, in_port_t port);

la_address_t *create_address_port(const char *ip, in_port_t port);

bool init_address(la_address_t *addr, const char *ip);

la_address_t *create_address(const char *ip);

la_address_t *dup_address(const la_address_t *address);

void free_address(la_address_t *address);

#endif /* __addresses_h */

/* vim: set autowrite expandtab: */
