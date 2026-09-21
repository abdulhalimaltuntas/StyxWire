/* 
 * $smu-mark$ 
 * $name: sendip.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: sendip.c,v 1.2 2004/04/09 23:38:56 antirez Exp $ */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "hping2.h"
#include "globals.h"
#include "output.h"

/* Build the IP header around 'data' and write the datagram to the raw
 * socket. Returns 0 on success, -1 when it could not be sent (the caller
 * stops: continuing would only repeat the failure). With --rand-dest and
 * --rand-source send errors are expected (unroutable addresses) and
 * ignored. */
int send_ip (char* src, char *dst, char *data, unsigned int datalen,
		int more_fragments, unsigned short fragoff, char *options,
		unsigned int optlen)
{
	char		*packet;
	int		result,
			packetsize;
	struct myiphdr	*ip;

	packetsize = IPHDR_SIZE + optlen + datalen;
	if ( (packet = malloc(packetsize)) == NULL) {
		perror("[send_ip] malloc()");
		return -1;
	}

	memset(packet, 0, packetsize);
	ip = (struct myiphdr*) packet;

	/* copy src and dst address */
	memcpy(&ip->saddr, src, sizeof(ip->saddr));
	memcpy(&ip->daddr, dst, sizeof(ip->daddr));

	/* build ip header */
	ip->version	= 4;
	ip->ihl		= (IPHDR_SIZE + optlen + 3) >> 2;
	ip->tos		= cfg.ip_tos;

#if defined OSTYPE_DARWIN || defined OSTYPE_FREEBSD || defined OSTYPE_NETBSD || defined OSTYPE_BSDI
/* FreeBSD */
/* NetBSD */
	ip->tot_len	= packetsize;
#else
/* Linux */
/* OpenBSD */
	ip->tot_len	= htons(packetsize);
#endif

	if (!cfg.opt_fragment)
	{
		ip->id		= (cfg.src_id == -1) ?
			htons((unsigned short) hping_rand()) :
			htons((unsigned short) cfg.src_id);
	}
	else /* if you need fragmentation id must not be randomic */
	{
		/* FIXME: when frag. enabled sendip_handler shold inc. ip->id */
		/*        for every frame sent */
		ip->id		= (cfg.src_id == -1) ?
			htons(getpid() & 255) :
			htons((unsigned short) cfg.src_id);
	}

#if defined OSTYPE_DARWIN || defined OSTYPE_FREEBSD || defined OSTYPE_NETBSD | defined OSTYPE_BSDI
/* FreeBSD */
/* NetBSD */
	ip->frag_off	|= more_fragments;
	ip->frag_off	|= fragoff >> 3;
#else
/* Linux */
/* OpenBSD */
	ip->frag_off	|= htons(more_fragments);
	ip->frag_off	|= htons(fragoff >> 3); /* shift three flags bit */
#endif

	ip->ttl		= cfg.src_ttl;
	if (cfg.opt_rawipmode)	ip->protocol = cfg.raw_ip_protocol;
	else if	(cfg.opt_icmpmode)	ip->protocol = 1;	/* icmp */
	else if (cfg.opt_udpmode)	ip->protocol = 17;	/* udp  */
	else			ip->protocol = 6;	/* tcp  */
	ip->check	= 0; /* always computed by the kernel */

	/* copies options */
	if (options != NULL)
		memcpy(packet+IPHDR_SIZE, options, optlen);

	/* copies data */
	memcpy(packet + IPHDR_SIZE + optlen, data, datalen);
	
    if (cfg.opt_debug == TRUE)
    {
        unsigned int i;

        for (i=0; i<packetsize; i++)
            printf("%.2X ", packet[i]&255);
        printf("\n");
    }
	if (cfg.opt_dry_run) {
		/* --dry-run: report the datagram instead of sending it, one
		 * IP datagram (fragments included) at a time. Under --json a
		 * "packet" event with the bytes as hex, otherwise a line. */
		int i;
		char *hex = malloc((size_t) packetsize * 2 + 1);
		if (hex != NULL) {
			for (i = 0; i < packetsize; i++)
				sprintf(hex + i*2, "%.2x", (unsigned char) packet[i]);
			if (output_json_enabled()) {
				out_begin("packet");
				out_ipv4("to", ctx.remote.sin_addr.s_addr);
				out_int("bytes", packetsize);
				out_str("hex", hex);
				out_end();
			} else {
				printf("dry-run: to %s, %d bytes: %s\n",
					inet_ntoa(ctx.remote.sin_addr), packetsize, hex);
			}
			free(hex);
		}
		free(packet);
		if (cfg.opt_safe && !ctx.eof_reached)
			cfg.src_id++;
		return 0;
	}
	result = sendto(ctx.sockraw, packet, packetsize, 0,
		(struct sockaddr*)&ctx.remote, sizeof(ctx.remote));
	free(packet);
	if (result == -1 && errno != EINTR && !cfg.opt_rand_dest && !cfg.opt_rand_source) {
		perror("[send_ip] sendto");
		return -1;
	}

	/* inc packet id for safe protocol */
	if (cfg.opt_safe && !ctx.eof_reached)
		cfg.src_id++;
	return 0;
}
