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

/* send_tcp() builds the TCP probe through the ARS packet engine instead of
 * laying the bytes out by hand, so there is one implementation of the TCP
 * header and its checksum, not two (KK-5 / work package B4). It builds only
 * the TCP segment; the IP header is prepended later by send_ip(). The IP
 * layer here exists solely so ARS can source the pseudo-header addresses
 * for the checksum -- its bytes are discarded.
 *
 * The output is byte-for-byte identical to the previous hand-built version;
 * tests/test_core.c:test_send_tcp_vectors() pins every field, including the
 * three deliberately-malformed behaviours the ARS defaults do NOT reproduce
 * on their own and which are re-applied by hand below:
 *
 *   --badcksum    ARS computes the correct checksum; cksum.c corrupts it as
 *                 ~(sum ^ 0x5555) == (~sum) ^ 0x5555, so XOR the result.
 *   -O/--tcpoff   forge the data offset: set it manually and tell ARS not
 *                 to recompute it (ARS_TAKE_TCP_HDRLEN).
 *   Solaris bug   the checksum field carries the segment length instead.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>

#include "hping2.h"
#include "globals.h"
#include "ars.h"

int send_tcp(void)
{
	struct ars_packet	p;
	struct ars_iphdr	*ip;
	struct ars_tcphdr	*tcp;
	unsigned char		*built = NULL;
	size_t			built_size, l4len, l4off;
	int			tcp_opt_size = cfg.opt_tcp_timestamp ? 12 : 0;
	int			tcp_layer, rc;

	ars_init(&p);

	/* IP layer: only saddr/daddr are read (by the pseudo-header checksum);
	 * the compiled IP header itself is thrown away. */
	ip = ars_add_iphdr(&p, 0);
	if (ip == NULL)
		goto nomem;
	memcpy(&ip->saddr, &ctx.local.sin_addr.s_addr, 4);
	memcpy(&ip->daddr, &ctx.remote.sin_addr.s_addr, 4);
	ip->protocol = 6; /* tcp */

	/* TCP header */
	tcp_layer = p.p_layer_nr;
	tcp = ars_add_tcphdr(&p, 0);
	if (tcp == NULL)
		goto nomem;
	tcp->th_sport	= htons(ctx.src_port);
	tcp->th_dport	= htons(cfg.dst_port);
	/* sequence number and ack are random if not set */
	tcp->th_seq	= (cfg.set_seqnum) ? htonl(cfg.tcp_seqnum) : htonl(hping_rand());
	tcp->th_ack	= (cfg.set_ack) ? htonl(cfg.tcp_ack) : htonl(hping_rand());
	tcp->th_win	= htons(cfg.src_winsize);
	tcp->th_flags	= cfg.tcp_th_flags;
	/* forge the data offset exactly as the hand-built path did (this is
	 * how -O/--tcpoff works); keep ARS from overwriting it. */
	tcp->th_off	= cfg.src_thoff + (tcp_opt_size >> 2);
	ars_set_flags(&p, tcp_layer, ARS_TAKE_TCP_HDRLEN);

	/* tcp timestamp option: two NOPs, then kind 8 / len 10, a random
	 * tsval and a zero tsecr -- the historical byte order. */
	if (cfg.opt_tcp_timestamp) {
		struct ars_tcpopt *ts;
		__u32 randts = hping_rand();

		if (ars_add_tcpopt(&p, ARS_TCPOPT_NOP) == NULL ||
		    ars_add_tcpopt(&p, ARS_TCPOPT_NOP) == NULL ||
		    (ts = ars_add_tcpopt(&p, ARS_TCPOPT_TIMESTAMP)) == NULL)
			goto nomem;
		memcpy(ts->un.timestamp.tsval, &randts, 4); /* random */
		memset(ts->un.timestamp.tsecr, 0, 4);       /* zero */
	}

	/* data */
	if (cfg.data_size) {
		char *data = ars_add_data(&p, cfg.data_size);
		if (data == NULL)
			goto nomem;
		data_handler(data, cfg.data_size);
	}

	if (ars_compile(&p) != -ARS_OK ||
	    ars_build_packet(&p, &built, &built_size) != -ARS_OK) {
		fprintf(stderr, "styxwire: send_tcp: %s\n",
			p.p_error ? p.p_error : "packet build failed");
		ars_destroy(&p);
		free(built);
		return -1;
	}

	/* the TCP segment is everything past the (discarded) IP header */
	l4len = ars_relative_size(&p, tcp_layer);
	l4off = built_size - l4len;
	tcp = (struct ars_tcphdr *) (built + l4off);

	/* re-apply the deliberately-malformed checksum behaviours */
	if (cfg.opt_badcksum)
		tcp->th_sum ^= 0x5555;
#ifdef STUPID_SOLARIS_CHECKSUM_BUG
	tcp->th_sum = (u_int16_t) l4len;
#endif

	/* adds this pkt in delaytable */
	delaytable_add(ctx.sequence, ctx.src_port, S_SENT);

	/* send packet */
	rc = send_ip_handler((char*) (built + l4off), (unsigned int) l4len);
	ars_destroy(&p);
	free(built);

	ctx.sequence++;	/* next sequence number */
	if (!cfg.opt_keepstill)
		ctx.src_port = (ctx.sequence + cfg.initsport) % 65536;

	if (cfg.opt_force_incdport)
		cfg.dst_port++;
	return rc;

nomem:
	fprintf(stderr, "styxwire: send_tcp: %s\n",
		p.p_error ? p.p_error : "out of memory building the packet");
	ars_destroy(&p);
	return -1;
}
