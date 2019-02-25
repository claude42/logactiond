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
#include <arpa/inet.h>
#include <stdlib.h>
# ifndef S_SPLINT_S
#include <syslog.h>
# endif
#include <errno.h>

#include "logactiond.h"
#include "nodelist.h"

/*
 * Check whether addr is in net (with prefix).
 *
 * From https://stackoverflow.com/questions/7213995/ip-cidr-match-function
 */
static bool
cidr4_match(struct in_addr addr, struct in_addr net, int prefix)
{
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
cidr6_match(struct in6_addr address, struct in6_addr network, uint8_t prefix)
{
	const uint32_t *a = address.s6_addr32;
	const uint32_t *n = network.s6_addr32;
//	const uint32_t *a = address.__u6_addr.__u6_addr32;
//	const uint32_t *n = network.__u6_addr.__u6_addr32;

	int bits_whole, bits_incomplete;
	bits_whole = prefix >> 5;         // number of whole u32
	bits_incomplete = prefix & 0x1F;  // number of bits in incomplete u32
	if (bits_whole) {
		if (memcmp(a, n, bits_whole << 2)) {
			return false;
		}
	}
	if (bits_incomplete) {
		uint32_t mask = htonl((0xFFFFFFFFu) << (32 - bits_incomplete));
		if ((a[bits_whole] ^ n[bits_whole]) & mask) {
			return false;
		}
	}
	return true;
}



/*
 * Compare to addresses. Return 0 if addresses are the same, return 1
 * otherwise.
 */

int
adrcmp(la_address_t *a1, la_address_t *a2)
{
        if (!a1 && !a2)
                return 0;

        if (!a1 || !a2)
                return 1;

        if (a1->af == a2->af)
        {
                if (a1->af == AF_INET && a1->addr.s_addr == a2->addr.s_addr)
                        return 0;
                else if (a1->af == AF_INET6 &&
                                !memcmp(&(a1->addr6), &(a2->addr6),
                                        sizeof(struct in6_addr)))
                        return 0;
        }

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

        la_debug("address_on_ignore_list(%s)", address->text);

        for (la_address_t *ign_address = ITERATE_ADDRESSES(la_config->ignore_addresses);
                        (ign_address = NEXT_ADDRESS(ign_address));)
        {
                if (address->af != ign_address->af)
                        continue;
                else if (address->af == AF_INET &&
                                cidr4_match(address->addr, ign_address->addr,
                                        ign_address->prefix))
                                return true;
                else if (address->af == AF_INET6 &&
                                memcmp(&(address->addr6),
                                        &(ign_address->addr6), sizeof(struct
                                                in6_addr)))
                        return true;
        }

        return false;
}

/*
 * Create an IPv4 address from string
 */

bool
create_address4(const char *ip, la_address_t *address)
{
        address->prefix = inet_net_pton(AF_INET, ip, &(address->addr),
                        sizeof(in_addr_t));

        if (address->prefix != -1)
        {
                address->af = AF_INET;
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
 * Compute CIDR prefix
 *
 * returns 0 on error.
 */

static unsigned int
get_prefix(int af, const char *ip)
{
        assert(af == AF_INET || af == AF_INET6); assert(ip);

        char *ptr = strchr(ip, '/');
        if (!ptr)
        {
                if (af == AF_INET)
                        return 32;
                else if (af == AF_INET6)
                        return 128;
        }

        errno = 0;
        long result = strtol(ptr+1, NULL, 10);
        if (!errno ||
                        (af == AF_INET && result > 32) ||
                        (af == AF_INET6 && result > 128))
                return 0;

        return result;
}


/*
 * Create an IPv6 address from string
 */

bool
create_address6(const char *ip, la_address_t *address)
{
        assert(ip);

        /* TODO: does not support prefix for IPv6 */
        int tmp = inet_pton(AF_INET6, ip, &(address->addr6));
        if (tmp == 1)
        {
                address->prefix = get_prefix(AF_INET6, ip);
                address->af = AF_INET6;
                return true;
        }
        else if (tmp == 0)
        {
                return false;
        }
        else
        {
                die_err("Problem converting IP address %s.", ip);
        }

        return 0; // avoid warning
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

        la_address_t *result = xmalloc(sizeof(la_address_t));

        if (!create_address4(ip, result))
        {
                if (!create_address6(ip, result))
                {
                        free(result);
                        return NULL;
                }
        }
        result->text = xstrdup(ip);
        return result;
}

/*
 * Duplicate address
 */

la_address_t *
dup_address(la_address_t *address)
{
        assert(address);
        la_debug("dup_address(%s)", address->text);

        la_address_t *result = xmalloc(sizeof(la_address_t));

        result->af = address->af;
        result->addr = address->addr;
        memcpy(&(result->addr6), &(address->addr6), sizeof(struct in6_addr));
        result->prefix = address->prefix;
        result->text = xstrdup(address->text);

        return result;
}

/*
 * Free single address. Must not be called with NULL argument
 */

void
free_address(la_address_t *address)
{
        assert(address);

        free(address->text);
        free(address);
}

/*
 * Free all addresses in list
 */

void
free_address_list(kw_list_t *list)
{
        if (!list)
                return;

        for (la_address_t *tmp; (tmp = REM_ADDRESSES_HEAD(list));)
                free_address(tmp);

        free(list);
}


/* vim: set autowrite expandtab: */
