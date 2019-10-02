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

#include <stdlib.h>
#include <netdb.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
/* keep these 3 in, even if deheader says to remote them. Necessary e.g. for
 * FreeBSD */
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

int
main(int argc, char *argv[])
{
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        struct addrinfo *res;

        hints.ai_flags = AI_PASSIVE | AI_V4MAPPED | AI_ADDRCONFIG;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;

        int r = getaddrinfo("nirvana.aw.net", "16473", &hints, &res);
        if (r)
                printf("Failed: %s\n", gai_strerror(r));

        for (; res; res = res->ai_next)
        {
                printf("Flags: %u\n", res->ai_flags);
                printf("Family 1: %u\n", res->ai_family);
                printf("Family 2: %u\n", res->ai_addr->sa_family);
                char *socktype = "unknown";
                if (res->ai_socktype == SOCK_STREAM)
                        socktype = "SOCK_STREAM";
                else if (res->ai_socktype == SOCK_DGRAM)
                        socktype = "SOCK_DGRAM";
                printf("Socktype: %s\n", socktype);

                if (res->ai_family == AF_INET)
                {
                        struct sockaddr_in *sa = (struct sockaddr_in *) res->ai_addr;
                        printf("Port: %u\n", ntohs(sa->sin_port));
                        char hostname[INET_ADDRSTRLEN];
                        printf("Address: %s\n", inet_ntop(AF_INET, &sa->sin_addr,
                                                hostname, INET_ADDRSTRLEN));
                }
                else
                {
                        struct sockaddr_in6 *sa = (struct sockaddr_in6 *) res->ai_addr;
                        printf("Port: %u\n", ntohs(sa->sin6_port));
                        char hostname[INET6_ADDRSTRLEN];
                        printf("Address: %s\n", inet_ntop(AF_INET6,
                                                &sa->sin6_addr, hostname,
                                                INET6_ADDRSTRLEN));
                }
                printf("Name: %s\n", res->ai_canonname);
                char numeric[INET6_ADDRSTRLEN];
                getnameinfo(res->ai_addr, res->ai_addrlen, numeric,
                                INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST);
                printf("Addstr: %s\n", numeric);
                printf("\n");
        }

        exit(0);
}


/* vim: set autowrite expandtab: */

