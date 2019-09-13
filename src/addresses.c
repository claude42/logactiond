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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>

#include "logactiond.h"
#include "nodelist.h"

void
assert_address_ffl(la_address_t *address, const char *func, char *file, unsigned int line)
{
        if (!address)
                die_hard("%s:%u: %s: Assertion 'address' failed. ", file, line,
                                func);
        if (address->af == AF_INET)
        {
                if (address->prefix<0 || address->prefix>32)
                        die_hard("%s:%u: %s: Assertion 'address->prefix<0 || "
                                        "address->prefix>32' failed.", file,
                                        line, func);
        }
        else if (address->af == AF_INET6)
        {
                if (address->prefix<0 || address->prefix>128)
                        die_hard("%s:%u: %s: Assertion 'address->prefix<0 || "
                                        "address->prefix>128' failed.", file,
                                        line, func);
        }
        else
        {
                die_hard("%s:%u: %s: Assertion 'address->af' failed.", file,
                                line, func);
        }
        if (!address->text)
                die_hard("%s:%u: %s: Assertion 'address->text' failed.", file,
                                line, func);
}

/*
 * Check whether addr is in net (with prefix).
 *
 * From https://stackoverflow.com/questions/7213995/ip-cidr-match-function
 */
static bool
cidr_match(struct in_addr addr, struct in_addr net, uint8_t prefix)
{
        la_vdebug("cidr_match()");

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

bool cidr6_match(struct in6_addr addr, struct in6_addr net, uint8_t prefix)
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
		uint32_t mask = htonl((0xFFFFFFFFu) << (32 - prefix_incomplete));
		if ((a[prefix_whole] ^ n[prefix_whole]) & mask)
			return false;
	}

	return true;
}

/*
 * Compare two addresses. Return 0 if addresses are the same, return 1
 * otherwise.
 */

int
adrcmp(la_address_t *a1, la_address_t *a2)
{
        assert(a1), assert(a2);
        la_vdebug("adrcmp(%s, %s)", a1->text, a2->text);

        /* if both are not NULL and of the address family, look further */
        if (a1 && a2 && a1->af == a2->af)
        {
                if (a1->af == AF_INET && a1->addr.s_addr == a2->addr.s_addr)
                        return 0;
                else if (a1->af == AF_INET6 &&
                                !memcmp(&(a1->addr6), &(a2->addr6),
                                        sizeof(struct in6_addr)))
                        return 0;
        }

        /* if both are NULL, they are the same (sort of) */
        if (!a1 && !a2)
                return 0;

        /* Return 1 otherwise, either if
         * - one of the two addresses is NULL, or
         * - address families differ, or
         * - addresses differ, or
         * - unknown address family
         */
        return 1;
}

/*
 * Check whether ip address is on ignore list. Returns false if address==NULL
 */

bool
address_on_ignore_list(la_address_t *address)
{
        if (!address)
                return false;

        assert_address(address);

        la_vdebug("address_on_ignore_list(%s)", address->text);

        assert(la_config);
        if (!la_config->ignore_addresses)
                return false;

        for (la_address_t *ign_address = ITERATE_ADDRESSES(la_config->ignore_addresses);
                        (ign_address = NEXT_ADDRESS(ign_address));)
        {
                if (address->af != ign_address->af)
                        continue;
                else if (address->af == AF_INET &&
                                cidr_match(address->addr, ign_address->addr,
                                        ign_address->prefix))
                                return true;
                else if (address->af == AF_INET6 &&
                                cidr6_match(address->addr6, ign_address->addr6,
                                        ign_address->prefix))
                        return true;
        }

        return false;
}

/*
 * Create an IPv4 address from string
 */

static bool
create_address4(const char *ip, la_address_t *address)
{
        assert(ip); assert(address); // can't do assert_address() just yet
        la_vdebug("create_address4(%s)", ip);
        address->prefix = inet_net_pton(AF_INET, ip, &(address->addr),
                        sizeof(in_addr_t));

        if (address->prefix != -1)
        {
                address->af = AF_INET;
                address->text = xstrdup(ip);
                return true;
        }
        else
        {
                if (errno != ENOENT)
                        die_err("Problem converting IP address %s.", ip);
                return false;
        }
}

/*
 * Create an IPv6 address from string
 */

static bool
create_address6(const char *ip, la_address_t *address)
{
        assert(ip); assert(address); // can't do assert_address() just yet
        la_vdebug("create_address6(%s)", ip);

        char *sep = strchr(ip, '/');
        if (sep)
                *sep = '\0';

        int tmp = inet_pton(AF_INET6, ip, &(address->addr6));
        if (tmp == 1)
        {
                if (sep)
                {
                        char *endptr;
                        address->prefix = strtol(sep + 1, &endptr, 10);
                        if (*endptr != '\0')
                                return false; // spurious characters after '/'
                        if (address->prefix < 0 || address->prefix > 128)
                                return false;
                }
                else
                {
                        address->prefix = 128;
                }
                address->af = AF_INET6;
                address->text = xmalloc(50);
                if (inet_ntop(AF_INET6, &(address->addr6), address->text, 50))
                {
                        return true;
                }
                {
                        free(address->text);
                        return false;
                }
        }
        else if (tmp == 0)
        {
                return false;
        }
        else
        {
                die_err("Problem converting IP address %s.", ip);
        }

        assert(false);
        return 0; // avoid compiler warning
}

/*
 * Create new la_address_t. ip must not be NULL
 *
 * Returns NULL in case of an invalid (textual representation of an) IP
 * address.
 */

la_address_t *
create_address(const char *ip)
{
        assert(ip);
        la_vdebug("create_address(%s)", ip);

        la_address_t *result = xmalloc(sizeof(la_address_t));

        if (!create_address4(ip, result))
        {
                if (!create_address6(ip, result))
                {
                        free(result);
                        return NULL;
                }
        }

        /* only reached in case IP address could be converted correctly */

        assert_address(result);
        return result;
}

/*
 * Duplicate address
 */

la_address_t *
dup_address(la_address_t *address)
{
        assert_address(address);
        la_vdebug("dup_address(%s)", address->text);

        la_address_t *result = xmalloc(sizeof(la_address_t));

        result->af = address->af;
        result->addr = address->addr;
        memcpy(&(result->addr6), &(address->addr6), sizeof(struct in6_addr));
        result->prefix = address->prefix;
        result->text = xstrdup(address->text);

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

        assert_address(address);
        la_vdebug("free_address(%s)", address->text);

        free(address->text);
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
