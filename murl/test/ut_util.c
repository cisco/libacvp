/*
Copyright (c) 2016, Cisco Systems, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


/*
 * Attempts to locate an IPv6 address on the local system that
 * can be used for IPv6 testing of Murl.
 * The address parameter should already be allocated.  The max_addr
 * parameter is the size of the address parameter allocation.
 *
 * Returns 0 if an address is found, non-zero if not.
 */
int test_murl_locate_ipv6_address (char *address, int max_addr)
{
    struct ifaddrs *ifaddr, *ifa;
    struct sockaddr_in6 *sin6;
    int have_v6_loopback = 0;

    if (getifaddrs(&ifaddr) == -1) {
	fprintf(stderr, "Unable to get local interface addresses!!!\n");
        return 1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;  

        if ((ifa->ifa_addr->sa_family==AF_INET6)) {
	    if (!strcmp(ifa->ifa_name, "lo")) {
		have_v6_loopback = 1;
		continue;
	    }
	    sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            /* Attempt to skip link local addresses */
            if (sin6->sin6_scope_id) continue;
	    memset(address, 0, max_addr);
	    if (!inet_ntop(AF_INET6, &sin6->sin6_addr, address, max_addr)) {
		fprintf(stderr, "inet_ntop failed!!!\n");
		freeifaddrs(ifaddr);
		return 1;
	    }

	    /*
	     * We found a v6 address that's not the loopback
	     */
            printf("\tFound IPv6 address : %s\n", address); 
	    freeifaddrs(ifaddr);
	    return 0;
        }
    }

    freeifaddrs(ifaddr);

    /*
     * Fallback to loopback address if we have it
     */
    if (have_v6_loopback) {
	strncpy(address, "::1", max_addr);
	return 0;
    } else {
	return 1;
    }

}
