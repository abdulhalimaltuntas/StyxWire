/* 
 * $smu-mark$ 
 * $name: sendtcp.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: sendtcp.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>

#include "hping2.h"
#include "globals.h"

int send_tcp(void)
{
	int rc;
	int			packet_size;
	int			tcp_opt_size = 0;
	char			*packet, *data;
	struct mytcphdr		*tcp;
	struct pseudohdr	*pseudoheader;
	unsigned char		*tstamp;

	if (cfg.opt_tcp_timestamp)
		tcp_opt_size = 12;

	packet_size = TCPHDR_SIZE + tcp_opt_size + cfg.data_size;
	packet = malloc(PSEUDOHDR_SIZE + packet_size);
	if (packet == NULL) {
		perror("[send_tcphdr] malloc()");
		return -1;
	}
	pseudoheader = (struct pseudohdr*) packet;
	tcp =  (struct mytcphdr*) (packet+PSEUDOHDR_SIZE);
	tstamp = (unsigned char*) (packet+PSEUDOHDR_SIZE+TCPHDR_SIZE);
	data = (char*) (packet+PSEUDOHDR_SIZE+TCPHDR_SIZE+tcp_opt_size);
	
	memset(packet, 0, PSEUDOHDR_SIZE+packet_size);

	/* tcp pseudo header */
	memcpy(&pseudoheader->saddr, &ctx.local.sin_addr.s_addr, 4);
	memcpy(&pseudoheader->daddr, &ctx.remote.sin_addr.s_addr, 4);
	pseudoheader->protocol		= 6; /* tcp */
	pseudoheader->lenght		= htons(TCPHDR_SIZE+tcp_opt_size+cfg.data_size);

	/* tcp header */
	tcp->th_dport	= htons(cfg.dst_port);
	tcp->th_sport	= htons(ctx.src_port);

	/* sequence number and ack are random if not set */
	tcp->th_seq = (cfg.set_seqnum) ? htonl(cfg.tcp_seqnum) : htonl(hping_rand());
	tcp->th_ack = (cfg.set_ack) ? htonl(cfg.tcp_ack) : htonl(hping_rand());

	tcp->th_off	= cfg.src_thoff + (tcp_opt_size >> 2);
	tcp->th_win	= htons(cfg.src_winsize);
	tcp->th_flags	= cfg.tcp_th_flags;

	/* tcp timestamp option */
	if (cfg.opt_tcp_timestamp) {
		__u32 randts = hping_rand();
		tstamp[0] = tstamp[1] = 1; /* NOOP */
		tstamp[2] = 8;
		tstamp[3] = 10; /* 10 bytes, kind+len+T1+T2 */
		memcpy(tstamp+4, &randts, 4); /* random */
		memset(tstamp+8, 0, 4); /* zero */
	}

	/* data */
	data_handler(data, cfg.data_size);

	/* compute checksum */
#ifdef STUPID_SOLARIS_CHECKSUM_BUG
	tcp->th_sum = packet_size;
#else
	tcp->th_sum = cksum((u_short*) packet, PSEUDOHDR_SIZE +
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
