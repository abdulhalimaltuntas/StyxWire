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
#include "ars.h"

/* send_udp() builds the UDP probe through the ARS packet engine (KK-5 / B4),
 * the same way send_tcp() does: the IP layer is present only so ARS can
 * source the pseudo-header addresses for the checksum, and the compiled IP
 * header is discarded (send_ip() prepends the real one). ARS fills the UDP
 * length and the checksum; --badcksum and the Solaris checksum-bug path are
 * re-applied by hand, since ars_cksum() does not honour opt_badcksum.
 * tests/test_core.c:test_send_udp_vectors() pins the bytes. */

int send_udp(void)
{
	struct ars_packet	p;
	struct ars_iphdr	*ip;
	struct ars_udphdr	*udp;
	unsigned char		*built = NULL;
	size_t			built_size, l4len, l4off;
	int			udp_layer, rc;

	ars_init(&p);

	/* IP layer: only saddr/daddr are read (pseudo-header checksum). */
	ip = ars_add_iphdr(&p, 0);
	if (ip == NULL)
		goto nomem;
	memcpy(&ip->saddr, &ctx.local.sin_addr.s_addr, 4);
	memcpy(&ip->daddr, &ctx.remote.sin_addr.s_addr, 4);
	ip->protocol = 17; /* udp */

	/* UDP header (ARS computes uh_ulen and uh_sum) */
	udp_layer = p.p_layer_nr;
	udp = ars_add_udphdr(&p, 0);
	if (udp == NULL)
		goto nomem;
	udp->uh_sport = htons(ctx.src_port);
	udp->uh_dport = htons(cfg.dst_port);

	/* data */
	if (cfg.data_size) {
		char *data = ars_add_data(&p, cfg.data_size);
		if (data == NULL)
			goto nomem;
		data_handler(data, cfg.data_size);
	}

	if (ars_compile(&p) != -ARS_OK ||
	    ars_build_packet(&p, &built, &built_size) != -ARS_OK) {
		fprintf(stderr, "styxwire: send_udp: %s\n",
			p.p_error ? p.p_error : "packet build failed");
		ars_destroy(&p);
		free(built);
		return -1;
	}

	/* the UDP segment is everything past the (discarded) IP header */
	l4len = ars_relative_size(&p, udp_layer);
	l4off = built_size - l4len;
	udp = (struct ars_udphdr *) (built + l4off);

	/* re-apply the deliberately-malformed checksum behaviours */
	if (cfg.opt_badcksum)
		udp->uh_sum ^= 0x5555;
#ifdef STUPID_SOLARIS_CHECKSUM_BUG
	udp->uh_sum = (u_int16_t) l4len;
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
	fprintf(stderr, "styxwire: send_udp: %s\n",
		p.p_error ? p.p_error : "out of memory building the packet");
	ars_destroy(&p);
	return -1;
}
