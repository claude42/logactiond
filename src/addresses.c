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

#include "logactiond.h"
#include "nodelist.h"

/*
 * From https://stackoverflow.com/questions/7213995/ip-cidr-match-function
 */
bool cidr_match(struct in_addr addr, struct in_addr net, uint8_t prefix) {
        if (prefix == 0) {
                // C99 6.5.7 (3): u32 << 32 is undefined behaviour
                return true;
        }

        return !((addr.s_addr ^ net.s_addr) & htonl(0xFFFFFFFFu << (32 - prefix)));
}


/*
 * Check whether ip address is on ignore list. Returns false if ip==NULL
 */

bool
address_on_ignore_list(const char *ip)
{
        struct in_addr addr;

        if (!ip)
                return false;

        la_debug("address_on_ignore_list(%s)", ip);

        if (inet_pton(AF_INET, ip, &addr) != 1)
                die_semantic("Invalid IP address!");

	for (la_address_t *address = (la_address_t *) la_config->ignore_addresses->head.succ;
			address->node.succ;
			address = (la_address_t *) address->node.succ)
	{
                if (cidr_match(addr, address->addr, address->prefix))
			return true;
	}

	return false;
}

/*
 * Create new la_address_t. ip must not be NULL
 */

la_address_t *
create_address(const char *ip)
{
        assert(ip);

	la_address_t *result = (la_address_t *) xmalloc(sizeof(la_address_t));

        result->prefix = inet_net_pton(AF_INET, ip, &(result->addr.s_addr),
                        sizeof(in_addr_t));

        if (result->prefix == -1)
                die_semantic("Invalid IP address!");

        la_debug("create_address(%s)=%u", ip, result->prefix);

	return result;
}

/* vim: set autowrite expandtab: */
