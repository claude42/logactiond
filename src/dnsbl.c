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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ndebug.h"
#include "addresses.h"
#include "dnsbl.h"
#include "logging.h"
#include "misc.h"

static unsigned int
convert_to_dnsbl_hostname_4_sa(const struct sockaddr_in *si,
                const char *dnsbl_domainname, char *hostname)
{
        uint8_t *b = (uint8_t *) &si->sin_addr;
        return snprintf(hostname, NI_MAXHOST, "%u.%u.%u.%u.%s", b[3], b[2],
                        b[1], b[0], dnsbl_domainname);
}

static unsigned int
convert_to_dnsbl_hostname_6_sa(const struct sockaddr_in6 *si6,
                const char *dnsbl_domainname, char *hostname)
{
        uint8_t *b = (uint8_t *) &si6->sin6_addr;
        return snprintf(hostname, NI_MAXHOST, "%x.%x.%x.%x.%x.%x.%x.%x.%x."
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

/*
 * hostname must be at least NI_MAXHOST characters long.
 *
 * Makes sure that there's a dot at the end of the hostname.
 */

static bool
convert_to_dnsbl_hostname_sa(const struct sockaddr *sa, const char *dnsbl_domainname, char *hostname)
{
        la_debug("convert_to_dnsbl_hostname_sa()");
        assert(sa); assert(dnsbl_domainname); assert(hostname);
        assert(xstrlen(hostname) < NI_MAXHOST);
        unsigned int r;

        if (sa->sa_family == AF_INET)
                r = convert_to_dnsbl_hostname_4_sa((struct  sockaddr_in *) sa,
                                dnsbl_domainname,  hostname);
        else
                r = convert_to_dnsbl_hostname_6_sa((struct  sockaddr_in6 *) sa,
                                dnsbl_domainname,  hostname);

        if (r>=NI_MAXHOST)
                return false;

        /* Make sure there's a dot at the end of the hostname to avoid lookups
         * of local domains like 1.2.3.4.sbl.spamhaus.org.localdomain.com */
        if (hostname[r-1] != '.')
        {
                if (r>=NI_MAXHOST-1)
                {
                        return false;
                }
                else
                {
                        hostname[r++] = '.';
                        hostname[r] = '\0';
                }
        }

        return true;
}

/*
 * hostname must be at least NI_MAXHOST characters long.
 */

static bool
convert_to_dnsbl_hostname(const la_address_t *address, const char *dnsbl_domainname, char *hostname)
{
        la_debug("convert_to_dnsbl_hostname()");
        return convert_to_dnsbl_hostname_sa((struct sockaddr *) &address->sa,
                        dnsbl_domainname, hostname);
}

bool
host_on_dnsbl(const la_address_t *address, const char *dnsbl_domainname)
{
        la_debug("host_on_dnsbl()");
        assert(address); assert(dnsbl_domainname);
        char hostname[NI_MAXHOST];
        struct addrinfo *ai;
        if (!convert_to_dnsbl_hostname(address, dnsbl_domainname, hostname))
                return false;

        const int r = getaddrinfo(hostname , NULL, NULL, &ai);

        if (!r)
                freeaddrinfo(ai);

        return !r;
}

/* Checks whether host is on any of the given blacklists. Return NULL if not
 * found, otherwise returns pointer to blacklists name.
 *
 * Do NOT free() the returned string!
 */

const char *
host_on_any_dnsbl(const kw_list_t *blacklists, const la_address_t *address)
{
        for (const kw_node_t *bl = &blacklists->head;
                        (bl = bl->succ->succ ? bl->succ : NULL);)
        {
                if (host_on_dnsbl(address, bl->name))
                        return bl->name;
        }
        
        return NULL;
}


/* vim: set autowrite expandtab: */
