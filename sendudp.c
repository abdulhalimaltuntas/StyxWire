/* 
 * $smu-mark$ 
 * $name: sendudp.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: sendudp.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>

#include "hping2.h"
#include "globals.h"

/* void hexdumper(unsigned char *packet, int size); */

int send_udp(void)
{
	int rc;
	int			packet_size;
	char			*packet, *data;
	struct myudphdr		*udp;
	struct pseudohdr *pseudoheader;

	packet_size = UDPHDR_SIZE + cfg.data_size;
	packet = malloc(PSEUDOHDR_SIZE + packet_size);
	if (packet == NULL) {
		perror("[send_udphdr] malloc()");
		return -1;
	}
	pseudoheader = (struct pseudohdr*) packet;
	udp =  (struct myudphdr*) (packet+PSEUDOHDR_SIZE);
	data = (char*) (packet+PSEUDOHDR_SIZE+UDPHDR_SIZE);
	
	memset(packet, 0, PSEUDOHDR_SIZE+packet_size);

	/* udp pseudo header */
	memcpy(&pseudoheader->saddr, &ctx.local.sin_addr.s_addr, 4);
	memcpy(&pseudoheader->daddr, &ctx.remote.sin_addr.s_addr, 4);
	pseudoheader->protocol		= 17; /* udp */
	pseudoheader->lenght		= htons(packet_size);

	/* udp header */
	udp->uh_dport	= htons(cfg.dst_port);
	udp->uh_sport	= htons(ctx.src_port);
	udp->uh_ulen	= htons(packet_size);

	/* data */
	data_handler(data, cfg.data_size);

	/* compute checksum */
#ifdef STUPID_SOLARIS_CHECKSUM_BUG
	udp->uh_sum = packet_size;
#else
	udp->uh_sum = cksum((__u16*) packet, PSEUDOHDR_SIZE +
		      packet_size);
#endif

	/* adds this pkt in delaytable */
	delaytable_add(ctx.sequence, ctx.src_port, S_SENT);

	/* send packet */
	rc = send_ip_handler(packet+PSEUDOHDR_SIZE, packet_size);
	free(packet);

	ctx.sequence++;	/* next sequence number */

	if (!cfg.opt_keepstill)
		ctx.src_port = (ctx.sequence + cfg.initsport) % 65536;

	if (cfg.opt_force_incdport)
		cfg.dst_port++;
	return rc;
}
