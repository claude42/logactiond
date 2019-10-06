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

#include <netdb.h>
#include <stdio.h>
#include <assert.h>

#include "logactiond.h"

/*
 * hostname must be at least NI_MAXHOST characters long.
 */

static bool
convert_to_dnsbl_hostname_sa(struct sockaddr *sa, char *dnsbl_domainname, char *hostname)
{
        la_debug("convert_to_dnsbl_hostname_sa()");
        assert(sa); assert(dnsbl_domainname); assert(hostname);
        int r;
        if (sa->sa_family == AF_INET)
        {
                struct sockaddr_in *si = (struct sockaddr_in *) sa;
                uint8_t *b = (uint8_t *) &si->sin_addr;
                r = snprintf(hostname, NI_MAXHOST, "%u.%u.%u.%u.%s", b[3], b[2],
                                b[1], b[0], dnsbl_domainname);
        }
        else
        {
                struct sockaddr_in6 *si6 = (struct sockaddr_in6 *) sa;
                uint8_t *b = (uint8_t *) &si6->sin6_addr;
                r = snprintf(hostname, NI_MAXHOST, "%x.%x.%x.%x.%x.%x.%x.%x.%x."
                                "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
                                "%x.%x.%x.%x.%x.%x.%x.%x.%x.%s",
                                b[15]&0x0f, b[15]>>4, b[14]&0x0f, b[14]>>4,
                                b[13]&0x0f, b[13]>>4, b[12]&0x0f, b[12]>>4,
                                b[11]&0x0f, b[11]>>4, b[10]&0x0f, b[10]>>4,
                                b[9]&0x0f, b[9]>>4, b[8]&0x0f, b[8]>>4,
                                b[7]&0x0f, b[7]>>4, b[6]&0x0f, b[6]>>4,
                                b[5]&0x0f, b[5]>>4, b[4]&0x0f, b[4]>>4,
                                b[3]&0x0f, b[3]>>4, b[2]&0x0f, b[2]>>4,
                                b[1]&0x0f, b[1]>>4, b[0]&0x0f, b[0]>>4,
                                dnsbl_domainname);
        }
        return r<=NI_MAXHOST;
}

/*
 * hostname must be at least NI_MAXHOST characters long.
 */

static bool
convert_to_dnsbl_hostname(la_address_t *address, char *dnsbl_domainname, char *hostname)
{
        la_debug("convert_to_dnsbl_hostname()");
        return convert_to_dnsbl_hostname_sa((struct sockaddr *) &address->sa, dnsbl_domainname, hostname);
}

bool
host_on_dnsbl(la_address_t *address, char *dnsbl_domainname)
{
        la_debug("host_on_dnsbl()");
        assert(address); assert(dnsbl_domainname);
        char hostname[NI_MAXHOST];
        struct addrinfo *ai;
        if (!convert_to_dnsbl_hostname(address, dnsbl_domainname, hostname))
                return false;

        int r = getaddrinfo(hostname , NULL, NULL, &ai);

        if (r)
        {
                return false;
        }
        else
        {
                freeaddrinfo(ai);
                return true;
        }
}



/* vim: set autowrite expandtab: */
