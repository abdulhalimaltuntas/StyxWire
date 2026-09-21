/* 
 * $smu-mark$ 
 * $name: resolve.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: resolve.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <stdlib.h>
#include <sys/types.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hping2.h"

/* Name resolution for the command line, IPv4 only.
 *
 * getaddrinfo(3) replaces the obsolete gethostbyname(3): it is thread
 * safe, it reports why a name failed, and it is the call an IPv6 capable
 * resolver will use. The packet path is still IPv4 only, so AF_INET is
 * requested here; a name or literal that only has an IPv6 address is
 * detected separately (resolve_is_ipv6_only) so that the user gets an
 * explicit "IPv6 is not supported by the command line yet" instead of a
 * misleading "unable to resolve". See docs/IPV6.txt.
 *
 * On error -1 is returned, on success 0. */
int resolve_addr(struct sockaddr *addr, char *hostname)
{
	struct sockaddr_in *address = (struct sockaddr_in *) addr;
	struct addrinfo hints, *res;

	memset(address, 0, sizeof(struct sockaddr_in));
	address->sin_family = AF_INET;

	/* a dotted quad needs no resolver */
	if (inet_pton(AF_INET, hostname, &address->sin_addr) == 1)
		return 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;	/* one entry per address, not per socket type */
	if (getaddrinfo(hostname, NULL, &hints, &res) != 0 || res == NULL)
		return -1;
	memcpy(&address->sin_addr,
	       &((struct sockaddr_in*) res->ai_addr)->sin_addr,
	       sizeof(address->sin_addr));
	freeaddrinfo(res);
	return 0;
}

/* Non-zero when 'hostname' is an IPv6 literal, or a name that resolves to
 * IPv6 addresses only. Used to turn the IPv4-only failure into an honest
 * diagnostic. */
int resolve_is_ipv6_only(const char *hostname)
{
	struct addrinfo hints, *res;
	struct in6_addr in6;
	struct in_addr in4;

	if (inet_pton(AF_INET6, hostname, &in6) == 1)
		return 1;
	if (inet_pton(AF_INET, hostname, &in4) == 1)
		return 0;

	/* does it have an IPv4 address? */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	if (getaddrinfo(hostname, NULL, &hints, &res) == 0 && res != NULL) {
		freeaddrinfo(res);
		return 0;
	}
	/* no IPv4: is it resolvable at all, as IPv6? */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	if (getaddrinfo(hostname, NULL, &hints, &res) == 0 && res != NULL) {
		freeaddrinfo(res);
		return 1;
	}
	return 0; /* it does not resolve at all: an ordinary failure */
}
