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

#include <string.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
/* keep these 3 in, even if deheader says to remove them. Necessary e.g. for
 * FreeBSD */
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <syslog.h>
#include <stdio.h>
#include <errno.h>

#include "ndebug.h"
#include "addresses.h"
#include "logging.h"
#include "misc.h"

void
assert_address_ffl(const la_address_t *address, const char *func,
                const char *file, unsigned int line)
{
        if (!address)
                die_hard("%s:%u: %s: Assertion 'address' failed. ", file, line,
                                func);
        if (address->sa.ss_family == AF_INET)
        {
                if (address->prefix<0 || address->prefix>32)
                        die_hard("%s:%u: %s: Assertion 'address->prefix>=0 && "
                                        "address->prefix<=32' failed.", file,
                                        line, func);
        }
        else if (address->sa.ss_family == AF_INET6)
        {
                if (address->prefix<0 || address->prefix>128)
                        die_hard("%s:%u: %s: Assertion 'address->prefix>=0 && "
                                        "address->prefix<=128' failed.", file,
                                        line, func);
        }
        else
        {
                die_hard("%s:%u: %s: Assertion 'address->af' failed.", file,
                                line, func);
        }
}

unsigned int
get_port(const la_address_t *address)
{
        assert_address(address);

        if (address->sa.ss_family == AF_INET)
        {
                struct sockaddr_in *sa = (struct sockaddr_in *) &address->sa;
                return ntohs(sa->sin_port);
        }
        else if (address->sa.ss_family == AF_INET6)
        {
                struct sockaddr_in6 *sa = (struct sockaddr_in6 *) &address->sa;
                return ntohs(sa->sin6_port);
        }
        else
        {
                return 0;
        }
}

/*
 * Return
 * - "4" - in case of AF_INET
 * - "6" - in case of AF_INET6
 * - "unknown" otherwise
 */

const char *
get_ip_version(const la_address_t *address)
{
	if (address->sa.ss_family == AF_INET)
		return "4";
	else if (address->sa.ss_family == AF_INET6)
		return "6";
	else
		return "unknown";
}

/*
 * Check whether addr is in net (with prefix).
 *
 * From https://stackoverflow.com/questions/7213995/ip-cidr-match-function
 */
static bool
cidr4_match(const struct in_addr addr, const struct in_addr net, const uint8_t prefix)
{
        la_vdebug("cidr4_match()");

        if (prefix == 0) {
                /* C99 6.5.7 (3): u32 << 32 is undefined behaviour */
                return true;
        }
        if (prefix >32) {
                /* make sure that we don't bitshift with a negative number
                 * below */
                return false;
        }

        return !((addr.s_addr ^ net.s_addr) & htonl(0xFFFFFFFFu << (32 - prefix)));
}

static bool
cidr6_match(const struct in6_addr addr, const struct in6_addr net, const uint8_t prefix)
{
        la_vdebug("cidr6_match()");
        assert(prefix<=128);

        /* Alas I'm not a IPv6 expert. But the following will make the source
         * compile at least on Linux and the BSDs (and thus MacOS). Not sure if
         * that will help on other platforms.
         */
#if !defined(s6_addr32)
#define s6_addr32 __u6_addr.__u6_addr32
#endif
	const uint32_t *a = addr.s6_addr32;
	const uint32_t *n = net.s6_addr32;

	int prefix_whole, prefix_incomplete;

	prefix_whole = prefix >> 5;         // number of whole u32
	prefix_incomplete = prefix & 0x1F;  // number of prefix in incomplete u32
	if (prefix_whole)
	{
		if (memcmp(a, n, prefix_whole << 2))
			return false;
	}

	if (prefix_incomplete)
	{
		const uint32_t mask = htonl((0xFFFFFFFFu) << (32 - prefix_incomplete));
		if ((a[prefix_whole] ^ n[prefix_whole]) & mask)
			return false;
	}

	return true;
}

static bool
cidr_match(const la_address_t *addr, const la_address_t *net)
{
        if (addr->sa.ss_family != net->sa.ss_family)
                return false;

        if (addr->sa.ss_family == AF_INET)
        {
                struct sockaddr_in *a = (struct sockaddr_in *) &addr->sa;
                struct sockaddr_in *n = (struct sockaddr_in *) &net->sa;
                return cidr4_match(a->sin_addr, n->sin_addr, net->prefix);
        }
        else if (addr->sa.ss_family == AF_INET6)
        {
                struct sockaddr_in6 *a = (struct sockaddr_in6 *) &addr->sa;
                struct sockaddr_in6 *n = (struct sockaddr_in6 *) &net->sa;
                return cidr6_match(a->sin6_addr, n->sin6_addr, net->prefix);
        }
        else
        {
                return false;
        }
}

/*
 * Compare two addresses. Return 0 if addresses are the same, return 1
 * otherwise.
 */

int
adrcmp(const la_address_t *a1, const la_address_t *a2)
{
        la_vdebug("adrcmp()");

        /* if both are not NULL and of the same address family, look further */
        if (a1 && a2 && a1->sa.ss_family == a2->sa.ss_family)
        {
                if (a1->sa.ss_family == AF_INET)
                {
                        struct sockaddr_in sa1 = *((struct sockaddr_in *) &a1->sa);
                        struct sockaddr_in sa2 = *((struct sockaddr_in *) &a2->sa);
                        if (sa1.sin_addr.s_addr == sa2.sin_addr.s_addr)
                                return 0;
                }
                else if (a1->sa.ss_family == AF_INET6)
                {
                        struct sockaddr_in6 sa1 = *((struct sockaddr_in6 *) &a1->sa);
                        struct sockaddr_in6 sa2 = *((struct sockaddr_in6 *) &a2->sa);
                        if (!memcmp(&sa1.sin6_addr, &sa2.sin6_addr,
                                                sizeof(struct in6_addr)))
                                return 0;
                }
        }
        /* if both are NULL, they are the same (sort of) */
        else if (!a1 && !a2)
        {
                return 0;
        }

        /* Return 1 otherwise, either if
         * - one of the two addresses is NULL, or
         * - address families differ, or
         * - addresses differ, or
         * - unknown address family
         */
        return 1;
}

/*
 * Check whether ip address is on a list. Returns false if address==NULL
 */

la_address_t *
address_on_list(const la_address_t *address, const kw_list_t *list)
{
        if (!address)
                return false;

        assert_address(address); assert_list(list);

        la_vdebug("address_on_list(%s)", address->text);

        for (la_address_t *list_address = ITERATE_ADDRESSES(list);
                        (list_address = NEXT_ADDRESS(list_address));)
        {
                if (cidr_match(address, list_address))
                        return list_address;
        }

        return NULL;
}

/*
 * Check whether ip address (represented by sockaddr) is on a list
 */

la_address_t *
address_on_list_sa(const struct sockaddr *sa, const socklen_t salen, const kw_list_t *list)
{
        la_address_t *address = create_address_sa(sa, salen);
        la_address_t *result = address_on_list(address, list);
        free(address);
        return result;
}

/*
 * Check whether ip address (represented by string) is on a list
 */

la_address_t *
address_on_list_str(const char *host, const kw_list_t *list)
{
        la_address_t *address = create_address(host);
        la_address_t *result = address_on_list(address, list);
        free(address);
        return result;
}

/*
 * Create new address based on sockaddr structure.
 */

la_address_t *
create_address_sa(const struct sockaddr *sa, const socklen_t salen)
{
        assert(sa);
        la_vdebug("create_address_sa()");

        if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)
                LOG_RETURN(NULL, LOG_ERR, "Unsupported address family!");

        la_address_t *result = xmalloc0(sizeof(la_address_t));

        memcpy(&(result->sa), sa, salen);

        if (getnameinfo(sa, salen, result->text,
                                MAX_ADDR_TEXT_SIZE + 1, NULL, 0, NI_NUMERICHOST))
        {
                free_address(result);
                return NULL;
        }

        result->prefix = sa->sa_family == AF_INET ? 32 : 128;

        return result;
}

/*
 * Creates new address. Sets correct port in address->sa
 *
 * Important: port must be supplied in host byte order NOT network byte order.
 *
 * May (briefly) modify host (but change it back  to its original state before
 * it returns.
 */

la_address_t *
create_address_port(const char *host, const in_port_t port)
{
        assert(host);
        la_vdebug("create_address_port(%s)", host);

        char *prefix_str = strchr(host, '/');
        if (prefix_str)
                *prefix_str = '\0';

        struct addrinfo *ai = NULL;

        char port_str[6];
        snprintf(port_str, 6, "%u", port);
        const int r = getaddrinfo(host, port ? port_str : NULL, NULL, &ai);

        switch (r) {
                case 0:
                        break;
                case EAI_AGAIN:
                case EAI_FAIL:
                case EAI_NONAME:
                        la_log(LOG_ERR, "Unable to get address for host '%s': %s",
                                        host, gai_strerror(r));
                        freeaddrinfo(ai);
                        return NULL;
                        break;
                default:
                        freeaddrinfo(ai);
                        die_hard("Error getting address for host '%s': %s",
                                        host, gai_strerror(r));
                        break;
        }

        if (prefix_str)
                *prefix_str = '/';
        
        /* We'll always only use the first address that getaddrinfo() returns.
         * That makes sense for send_to (as we don't want to send the same
         * message to the same host multiple times).
         *
         * TODO: But for ignore_addresses it might make more sense to go through all
         * results from getaddrinfo(). */

        la_address_t *result = create_address_sa(ai->ai_addr, ai->ai_addrlen);
        if (!result)
        {
                freeaddrinfo(ai);
                return NULL;
        }

        if (prefix_str)
        {
                char *endptr;
                errno = 0;
                result->prefix = strtol(prefix_str+1, &endptr, 10);
                /* Fail if there are spurious characters or prefix is out of
                 * bounds */
                if (errno || *endptr != '\0' || result->prefix < 0 ||
                                (ai->ai_family == AF_INET && result->prefix > 32) ||
                                (ai->ai_family == AF_INET6 && result->prefix > 128))
                {
                        freeaddrinfo(ai);
                        free_address(result);
                        LOG_RETURN(NULL, LOG_ERR, "Cannot convert address prefix!");
                }

                strncat(result->text, prefix_str, 4);
        }

        freeaddrinfo(ai);

        return result;
}

la_address_t *
create_address(const char *host)
{
        return create_address_port(host, 0);
}

/*
 * Duplicate address
 */

la_address_t *
dup_address(const la_address_t *address)
{
        assert_address(address);
        la_vdebug("dup_address(%s)", address->text);

        la_address_t *result = xmalloc(sizeof(la_address_t));

        memcpy(&(result->sa), &(address->sa), sizeof(struct sockaddr_storage));
        result->prefix = address->prefix;
        string_copy(result->text, MAX_ADDR_TEXT_SIZE + 1, address->text, 0);

        assert_address(result);
        return result;
}

/*
 * Free single address. Does nothing when argument is NULL
 */

void
free_address(la_address_t *address)
{
        if (!address)
                return;

        la_vdebug("free_address(%s)", address->text);

        free(address);
}

/*
 * Free all addresses in list
 */

void
empty_address_list(kw_list_t *list)
{
        la_vdebug("free_address_list()");
        if (!list)
                return;
        assert_list(list);

        for (la_address_t *tmp; (tmp = REM_ADDRESSES_HEAD(list));)
                free_address(tmp);
}

void
free_address_list(kw_list_t *list)
{
        empty_address_list(list);

        free(list);
}


/* vim: set autowrite expandtab: */
