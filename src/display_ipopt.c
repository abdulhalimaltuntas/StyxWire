/*
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* $Id: display_ipopt.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hping2.h"
#include "globals.h"

/* ripped from ping, bounds checking added.
 *
 * 'buf' points to an IP header whose IHL bytes are known to be present
 * (wait_packet() checks ihl*4 against the captured length before calling
 * this function). The option area is therefore at most 40 bytes long and
 * every access is kept inside it. */

void display_ipopt(char* buf)
{
	int i, j, optlen, hlen, naddr;
	unsigned long l;
	static int old_rrlen;
	static char old_rr[MAX_IPOPTLEN];
	unsigned char *cp, *addr;
	struct myiphdr ip;
	struct in_addr in;

	memcpy(&ip, buf, sizeof(ip)); /* alignment safe copy */
	hlen = ip.ihl * 4;
	if (hlen <= (int)sizeof(struct myiphdr))
		return; /* no options */
	if (hlen > (int)sizeof(struct myiphdr) + MAX_IPOPTLEN)
		hlen = sizeof(struct myiphdr) + MAX_IPOPTLEN;

	cp = (unsigned char *)buf + sizeof(struct myiphdr);
	hlen -= sizeof(struct myiphdr); /* bytes of option area left */

	while (hlen > 0) {
		switch (*cp) {
		case IPOPT_EOL:
			hlen = 0;
			break;
		case IPOPT_NOP:
			(void)printf("NOP\n");
			cp++; hlen--;
			break;
		default:
			/* Every other option has a length byte, which must
			 * cover at least itself and the type byte and must
			 * not exceed the option area. */
			if (hlen < 2 || cp[1] < 2 || cp[1] > hlen) {
				(void)printf("[|ipopt]\n");
				hlen = 0;
				break;
			}
			optlen = cp[1];
			switch (*cp) {
			case IPOPT_LSRR:
			case IPOPT_SSRR:
				(void)printf(*cp == IPOPT_LSRR ? "LSRR: " : "SSRR: ");
				/* type, len, ptr, then 4-byte addresses */
				naddr = (optlen - 3) / 4;
				addr = cp + 3;
				for (i = 0; i < naddr; i++) {
					l = ((unsigned long)addr[0] << 24) |
					    ((unsigned long)addr[1] << 16) |
					    ((unsigned long)addr[2] << 8) |
					     (unsigned long)addr[3];
					in.s_addr = htonl(l);
					printf("\t%s", inet_ntoa(in));
					if (i + 1 < naddr)
						(void)putchar('\n');
					addr += 4;
				}
				(void)putchar('\n');
				break;
			case IPOPT_RR:
				j = optlen;		/* length */
				i = optlen >= 3 ? cp[2] : 0; /* pointer */
				if (i > j)
					i = j;
				i -= IPOPT_MINOFF;	/* bytes of addresses recorded */
				if (i <= 0)
					break;
				/* ceil(i/4) addresses, but never beyond
				 * the option itself */
				naddr = (i + 3) / 4;
				if (naddr > (optlen - 3) / 4)
					naddr = (optlen - 3) / 4;
				if (naddr <= 0)
					break;
				i = naddr * 4;
				addr = cp + 3;
				if (i == old_rrlen
				    && cp == (unsigned char *)buf + sizeof(struct myiphdr)
				    && !memcmp((char *)addr, old_rr, i)) {
					(void)printf("\t(same route)\n");
					break;
				}
				old_rrlen = i;
				memcpy(old_rr, addr, i);
				(void)printf("RR: ");
				for (j = 0; j < naddr; j++) {
					l = ((unsigned long)addr[0] << 24) |
					    ((unsigned long)addr[1] << 16) |
					    ((unsigned long)addr[2] << 8) |
					     (unsigned long)addr[3];
					in.s_addr = htonl(l);
					printf("\t%s", inet_ntoa(in));
					if (j + 1 < naddr)
						(void)putchar('\n');
					addr += 4;
				}
				putchar('\n');
				break;
			default:
				(void)printf("unknown option %x\n", *cp);
				break;
			}
			cp += optlen;
			hlen -= optlen;
			break;
		}
	}
}
