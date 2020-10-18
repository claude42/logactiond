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
#include <stdbool.h>
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
                const char *file, int line)
{
        if (!address)
                die_hard("%s:%u: %s: Assertion 'address' failed. ", file, line,
                                func);
        switch (address->sa.ss_family)
        {
        case AF_INET:
                if (address->prefix<0 || address->prefix>32)
                        die_hard("%s:%u: %s: Assertion 'address->prefix>=0 && "
                                        "address->prefix<=32' failed.", file,
                                        line, func);
                break;
        case AF_INET6:
                if (address->prefix<0 || address->prefix>128)
                        die_hard("%s:%u: %s: Assertion 'address->prefix>=0 && "
                                        "address->prefix<=128' failed.", file,
                                        line, func);
                break;
        default:
                die_hard("%s:%u: %s: Assertion 'address->af' failed.", file,
                                line, func);
                break;
        }
}

int
get_port(const la_address_t *const address)
{
        assert_address(address);

        switch (address->sa.ss_family)
        {
        case AF_INET:
                return ntohs(((struct sockaddr_in *) &address->sa)->sin_port);
                break;
        case AF_INET6:
                return ntohs(((struct sockaddr_in6 *) &address->sa)->sin6_port);
                break;
        default:
                return 0;
                break;
        }
}

/*
 * Return
 * - "4" - in case of AF_INET
 * - "6" - in case of AF_INET6
 * - "unknown" otherwise
 */

const char *
get_ip_version(const la_address_t *const address)
{
        switch (address->sa.ss_family)
        {
        case AF_INET:
		return "4";
                break;
        case AF_INET6:
		return "6";
                break;
        default:
		return "unknown";
                break;
        }
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

	int prefix_whole = prefix >> 5;         // number of whole u32
	int prefix_incomplete = prefix & 0x1F;  // number of prefix in incomplete u32
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
cidr_match_sa(const struct sockaddr *sa, const la_address_t *const net)
{
        if (sa->sa_family != net->sa.ss_family)
                return false;

        switch (sa->sa_family)
        {
        case AF_INET:
                return cidr4_match(((struct sockaddr_in *) sa)->sin_addr,
                                ((struct sockaddr_in *) &net->sa)->sin_addr,
                                net->prefix);
                break;
        case AF_INET6:
                return cidr6_match(((struct sockaddr_in6 *) sa)->sin6_addr,
                                ((struct sockaddr_in6 *) &net->sa)->sin6_addr,
                                net->prefix);
                break;
        default:
                return false;
                break;
        }
}

/*
 * Compare two addresses. Return 0 if addresses are the same, return value < 0
 * if * first address is smaller a value > 0 if it's larger than second address.
 *
 * Return 127 in case 
 * - one of the two addresses is NULL, or
 * - address families differ, or
 * - unknown address family
 */

int
adrcmp(const la_address_t *const a1, const la_address_t *const a2)
{
        la_vdebug("adrcmp(%s, %s)", a1 ? a1->text : "NULL",
                        a2 ? a2->text : "NULL");

        /* if both are not NULL and of the same address family, look further */
        if (a1 && a2 && a1->sa.ss_family == a2->sa.ss_family)
        {
                if (a1->sa.ss_family == AF_INET)
                {
                        struct sockaddr_in sa1 = *((struct sockaddr_in *) &a1->sa);
                        struct sockaddr_in sa2 = *((struct sockaddr_in *) &a2->sa);
                        return ntohl(sa1.sin_addr.s_addr) - ntohl(sa2.sin_addr.s_addr);
                }
                else if (a1->sa.ss_family == AF_INET6)
                {
                        struct sockaddr_in6 sa1 = *((struct sockaddr_in6 *) &a1->sa);
                        struct sockaddr_in6 sa2 = *((struct sockaddr_in6 *) &a2->sa);

                        for (int i=0; i<16; i++)
                        {
                                const int result = sa1.sin6_addr.s6_addr[i] - sa2.sin6_addr.s6_addr[i];
                                if (result)
                                        return result;
                        }
                        return 0;
                }
        }
        /* if both are NULL, they are the same (sort of) */
        else if (!a1 && !a2)
        {
                return 0;
        }

        /* Return 127 otherwise, either if
         * - one of the two addresses is NULL, or
         * - address families differ, or
         * - unknown address family
         *
         * TODO: or should we rather die_err() in these cases?
         */
        return 127;
}

la_address_t *
address_on_list_sa(const struct sockaddr *const sa, const kw_list_t *const list)
{
        assert(sa); assert_list(list);

        for (la_address_t *list_address = ITERATE_ADDRESSES(list);
                        (list_address = NEXT_ADDRESS(list_address));)
        {
                if (cidr_match_sa(sa, list_address))
                        return list_address;
        }

        return NULL;
}

/*
 * Check whether ip address is on a list. Returns false if address==NULL
 */

la_address_t *
address_on_list(const la_address_t *const address, const kw_list_t *const list)
{
        return address_on_list_sa((struct sockaddr *) &(address->sa), list);
}

/*
 * Check whether ip address (represented by sockaddr) is on a list
 */

/*
 * Check whether ip address (represented by string) is on a list
 */

la_address_t *
address_on_list_str(const char *const host, const kw_list_t *const list)
{
        la_address_t address;
        if (!init_address(&address, host))
                return NULL;

        la_address_t *const result = address_on_list(&address, list);
        return result;
}

/*
 * Create new address based on sockaddr structure.
 */

static bool
create_address_sa_a(la_address_t *const addr, const struct sockaddr *const sa,
                const socklen_t salen)
{
        assert(sa);
        la_vdebug("create_address_sa()");

        if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)
                LOG_RETURN(false, LOG_ERR, "Unsupported address family!");

        memcpy(&(addr->sa), sa, salen);

        /* TODO better error handling */
        if (getnameinfo(sa, salen, addr->text,
                                MAX_ADDR_TEXT_SIZE + 1, NULL, 0, NI_NUMERICHOST))
                LOG_RETURN(false, LOG_ERR, "getnameinfo failed.");

        addr->prefix = sa->sa_family == AF_INET ? 32 : 128;

        return true;
}

static la_address_t *
create_address_sa(const struct sockaddr *const sa, const socklen_t salen)
{
        la_address_t *const result = xmalloc0(sizeof *result);

        if (!create_address_sa_a(result, sa, salen))
        {
                free(result);
                return NULL;
        }
        else
        {
                return result;
        }
}

/* Return prefix if valid prefix, -1 otherwise */

static int convert_prefix(unsigned short int family, const char *const prefix)
{
        assert(prefix);
        assert(family == AF_INET || family == AF_INET6);

        if (prefix[0] == '\0')
                return -1;

        char *endptr;
        errno = 0;
        const int result = strtol(prefix, &endptr, 10);
        /* Fail if there are spurious characters or prefix is out of
         * bounds */
        if (errno || !endptr || *endptr != '\0' || result < 0 ||
                        (family == AF_INET && result > 32) ||
                        (family == AF_INET6 && result > 128))
                return -1;

        return result;
}

/*
 * Creates new address. Sets correct port in address->sa
 *
 * Important: port must be supplied in host byte order NOT network byte order.
 */

bool
init_address_port(la_address_t *const addr, const char *const host, const in_port_t port)
{
        assert(host);
        la_vdebug("create_address_port(%s)", host);

        char host_str[INET6_ADDRSTRLEN +1];
        const int n = string_copy(host_str, INET6_ADDRSTRLEN, host, 0, '/');
        if (n == -1)
                die_hard("Address string too long!");

        // Prefix - if any. String will include '/'
        const char *const prefix_str = host[n] == '/' ? &host[n] : NULL;

        char port_str[6];
        if (port)
                snprintf(port_str, 6, "%u", port);

        struct addrinfo *ai = NULL;
        const int r = getaddrinfo(host_str, port ? port_str : NULL, NULL, &ai);

        switch (r) {
                case 0:
                        break;
                case EAI_AGAIN:
                case EAI_FAIL:
                case EAI_NONAME:
                        la_log(LOG_ERR, "Unable to get address for host '%s': %s",
                                        host_str, gai_strerror(r));
                        freeaddrinfo(ai);
                        return false;
                        break;
                default:
                        freeaddrinfo(ai);
                        die_hard("Error getting address for host '%s': %s",
                                        host_str, gai_strerror(r));
                        break;
        }

        /* We'll always only use the first address that getaddrinfo() returns.
         * That makes sense for send_to (as we don't want to send the same
         * message to the same host multiple times).
         *
         * TODO: But for ignore_addresses it might make more sense to go through all
         * results from getaddrinfo(). */

        if (!create_address_sa_a(addr, ai->ai_addr, ai->ai_addrlen))
        {
                freeaddrinfo(ai);
                return false;
        }

        if (prefix_str)
        {
                addr->prefix = convert_prefix(ai->ai_family, prefix_str + 1);
                if (addr->prefix == -1)
                {
                        freeaddrinfo(ai);
                        LOG_RETURN(false, LOG_ERR, "Cannot convert address prefix!");
                }

                strncat(addr->text, prefix_str, 4);
        }

        freeaddrinfo(ai);

        return true;
}

la_address_t *
create_address_port(const char *const host, const in_port_t port)
{
        la_address_t *const result = xmalloc0(sizeof *result);

        if (!init_address_port(result, host, port))
        {
                free(result);
                return NULL;
        }
        else
        {
                return result;
        }
}

bool
init_address(la_address_t *const addr, const char *const host)
{
        return init_address_port(addr, host, 0);
}

la_address_t *
create_address(const char *const host)
{
        return create_address_port(host, 0);
}

/*
 * Duplicate address
 */

la_address_t *
dup_address(const la_address_t *const address)
{
        assert_address(address);
        la_vdebug("dup_address(%s)", address->text);

        la_address_t *const result = xmalloc(sizeof *result);

        memcpy(&(result->sa), &(address->sa), sizeof (struct sockaddr_storage));
        result->prefix = address->prefix;
        string_copy(result->text, MAX_ADDR_TEXT_SIZE + 1, address->text, 0, '\0');

        assert_address(result);
        return result;
}

/*
 * Free single address. Does nothing when argument is NULL
 */

void
free_address(la_address_t *const address)
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
empty_address_list(kw_list_t *const list)
{
        la_vdebug("free_address_list()");
        if (!list)
                return;
        assert_list(list);

        for (la_address_t *tmp; (tmp = REM_ADDRESSES_HEAD(list));)
                free_address(tmp);
}

void
free_address_list(kw_list_t *const list)
{
        empty_address_list(list);

        free(list);
}


/* vim: set autowrite expandtab: */
