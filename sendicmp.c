/* 
 * $smu-mark$ 
 * $name: sendicmp.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: sendicmp.c,v 1.1.1.1 2003/08/31 17:23:53 antirez Exp $ */

#include <sys/types.h> /* this should be not needed, but ip_icmp.h lacks it */
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "hping2.h"
#include "globals.h"

static int _icmp_seq = 0;

int send_icmp_echo(void);
int send_icmp_other(void);
int send_icmp_timestamp(void);
int send_icmp_address(void);

/* Non zero when 'type' is one of the ICMP types hping knows how to build
 * (others need --force-icmp). parse_options() uses it too. */
int icmp_type_supported(int type)
{
	switch(type) {
	case ICMP_ECHO: case ICMP_ECHOREPLY:
	case ICMP_DEST_UNREACH: case ICMP_SOURCE_QUENCH:
	case ICMP_REDIRECT: case ICMP_TIME_EXCEEDED:
	case ICMP_TIMESTAMP: case ICMP_TIMESTAMPREPLY:
	case ICMP_ADDRESS: case ICMP_ADDRESSREPLY:
		return 1;
	}
	return 0;
}

int send_icmp(void)
{
	switch(cfg.opt_icmptype)
	{
		case ICMP_ECHO:			/* type 8 */
		case ICMP_ECHOREPLY:		/* type 0 */
			return send_icmp_echo();
		case ICMP_DEST_UNREACH:		/* type 3 */
		case ICMP_SOURCE_QUENCH:	/* type 4 */
		case ICMP_REDIRECT:		/* type 5 */
		case ICMP_TIME_EXCEEDED:	/* type 11 */
			return send_icmp_other();
		case ICMP_TIMESTAMP:
		case ICMP_TIMESTAMPREPLY:
			return send_icmp_timestamp();
		case ICMP_ADDRESS:
		case ICMP_ADDRESSREPLY:
			return send_icmp_address();
		default:
			if (cfg.opt_force_icmp)
				return send_icmp_other();
			/* parse_options() rejects this earlier */
			fprintf(stderr, "[send_icmp] Unsupported icmp type!\n");
			return -1;
	}
}

int send_icmp_echo(void)
{
	int rc;
	char *packet, *data;
	struct myicmphdr *icmp;

	packet = malloc(ICMPHDR_SIZE + cfg.data_size);
	if (packet == NULL) {
		perror("[send_icmp] malloc");
		return -1;
	}

	memset(packet, 0, ICMPHDR_SIZE + cfg.data_size);

	icmp = (struct myicmphdr*) packet;
	data = packet + ICMPHDR_SIZE;

	/* fill icmp hdr */
	icmp->type = cfg.opt_icmptype;	/* echo replay or echo request */
	icmp->code = cfg.opt_icmpcode;	/* should be indifferent */
	icmp->checksum = 0;
	icmp->un.echo.id = getpid() & 0xffff;
	icmp->un.echo.sequence = _icmp_seq;

	/* data */
	data_handler(data, cfg.data_size);

	/* icmp checksum */
	if (cfg.icmp_cksum == -1)
		icmp->checksum = cksum((u_short*)packet, ICMPHDR_SIZE + cfg.data_size);
	else
		icmp->checksum = cfg.icmp_cksum;

	/* adds this pkt in delaytable */
	if (cfg.opt_icmptype == ICMP_ECHO)
		delaytable_add(_icmp_seq, 0, S_SENT);

	/* send packet */
	rc = send_ip_handler(packet, ICMPHDR_SIZE + cfg.data_size);
	free (packet);

	_icmp_seq++;
	return rc;
}

int send_icmp_timestamp(void)
{
	int rc;
	char *packet;
	struct myicmphdr *icmp;
	struct icmp_tstamp_data *tstamp_data;

	packet = malloc(ICMPHDR_SIZE + sizeof(struct icmp_tstamp_data));
	if (packet == NULL) {
		perror("[send_icmp] malloc");
		return -1;
	}

	memset(packet, 0, ICMPHDR_SIZE + sizeof(struct icmp_tstamp_data));

	icmp = (struct myicmphdr*) packet;
	tstamp_data = (struct icmp_tstamp_data*) (packet + ICMPHDR_SIZE);

	/* fill icmp hdr */
	icmp->type = cfg.opt_icmptype;	/* echo replay or echo request */
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.id = getpid() & 0xffff;
	icmp->un.echo.sequence = _icmp_seq;
	tstamp_data->orig = htonl(get_midnight_ut_ms());
	tstamp_data->recv = tstamp_data->tran = 0;

	/* icmp checksum */
	if (cfg.icmp_cksum == -1)
		icmp->checksum = cksum((u_short*)packet, ICMPHDR_SIZE +
				sizeof(struct icmp_tstamp_data));
	else
		icmp->checksum = cfg.icmp_cksum;

	/* adds this pkt in delaytable */
	if (cfg.opt_icmptype == ICMP_TIMESTAMP)
		delaytable_add(_icmp_seq, 0, S_SENT);

	/* send packet */
	rc = send_ip_handler(packet, ICMPHDR_SIZE + sizeof(struct icmp_tstamp_data));
	free (packet);

	_icmp_seq++;
	return rc;
}

int send_icmp_address(void)
{
	int rc;
	char *packet;
	struct myicmphdr *icmp;

	packet = malloc(ICMPHDR_SIZE + 4);
	if (packet == NULL) {
		perror("[send_icmp] malloc");
		return -1;
	}

	memset(packet, 0, ICMPHDR_SIZE + 4);

	icmp = (struct myicmphdr*) packet;

	/* fill icmp hdr */
	icmp->type = cfg.opt_icmptype;	/* echo replay or echo request */
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.id = getpid() & 0xffff;
	icmp->un.echo.sequence = _icmp_seq;
	memset(packet+ICMPHDR_SIZE, 0, 4);

	/* icmp checksum */
	if (cfg.icmp_cksum == -1)
		icmp->checksum = cksum((u_short*)packet, ICMPHDR_SIZE + 4);
	else
		icmp->checksum = cfg.icmp_cksum;

	/* adds this pkt in delaytable */
	if (cfg.opt_icmptype == ICMP_TIMESTAMP)
		delaytable_add(_icmp_seq, 0, S_SENT);

	/* send packet */
	rc = send_ip_handler(packet, ICMPHDR_SIZE + 4);
	free (packet);

	_icmp_seq++;
	return rc;
}

int send_icmp_other(void)
{
	int rc;
	char *packet, *data, *ph_buf;
	struct myicmphdr *icmp;
	struct myiphdr icmp_ip;
	struct myudphdr *icmp_udp;
	int udp_data_len = 0;
	struct pseudohdr *pseudoheader;
	int left_space = IPHDR_SIZE + UDPHDR_SIZE + cfg.data_size;

	packet = malloc(ICMPHDR_SIZE + IPHDR_SIZE + UDPHDR_SIZE + cfg.data_size);
	ph_buf = malloc(PSEUDOHDR_SIZE + UDPHDR_SIZE + udp_data_len);
	if (packet == NULL || ph_buf == NULL) {
		perror("[send_icmp] malloc");
		free(packet);
		free(ph_buf);
		return -1;
	}

	memset(packet, 0, ICMPHDR_SIZE + IPHDR_SIZE + UDPHDR_SIZE + cfg.data_size);
	memset(ph_buf, 0, PSEUDOHDR_SIZE + UDPHDR_SIZE + udp_data_len);

	icmp = (struct myicmphdr*) packet;
	data = packet + ICMPHDR_SIZE;
	pseudoheader = (struct pseudohdr *) ph_buf;
	icmp_udp = (struct myudphdr *) (ph_buf + PSEUDOHDR_SIZE);

	/* fill icmp hdr */
	icmp->type = cfg.opt_icmptype;	/* ICMP_TIME_EXCEEDED */
	icmp->code = cfg.opt_icmpcode;	/* should be 0 (TTL) or 1 (FRAGTIME) */
	icmp->checksum = 0;
	if (cfg.opt_icmptype == ICMP_REDIRECT)
		memcpy(&icmp->un.gateway, &ctx.icmp_gw.sin_addr.s_addr, 4);
	else
		icmp->un.gateway = 0;	/* not used, MUST be 0 */

	/* concerned packet headers */
	/* IP header */
	icmp_ip.version  = cfg.icmp_ip_version;		/* 4 */
	icmp_ip.ihl      = cfg.icmp_ip_ihl;			/* IPHDR_SIZE >> 2 */
	icmp_ip.tos      = cfg.icmp_ip_tos;			/* 0 */
	icmp_ip.tot_len  = htons((cfg.icmp_ip_tot_len ? cfg.icmp_ip_tot_len : (cfg.icmp_ip_ihl<<2) + UDPHDR_SIZE + udp_data_len));
	icmp_ip.id       = htons(getpid() & 0xffff);
	icmp_ip.frag_off = 0;				/* 0 */
	icmp_ip.ttl      = 64;				/* 64 */
	icmp_ip.protocol = cfg.icmp_ip_protocol;		/* 6 (TCP) */
	icmp_ip.check	 = 0;
	memcpy(&icmp_ip.saddr, &ctx.icmp_ip_src.sin_addr.s_addr, 4);
	memcpy(&icmp_ip.daddr, &ctx.icmp_ip_dst.sin_addr.s_addr, 4);
	icmp_ip.check	 = cksum((__u16 *) &icmp_ip, IPHDR_SIZE);

	/* UDP header */
	memcpy(&pseudoheader->saddr, &ctx.icmp_ip_src.sin_addr.s_addr, 4);
	memcpy(&pseudoheader->daddr, &ctx.icmp_ip_dst.sin_addr.s_addr, 4);
	pseudoheader->protocol = icmp_ip.protocol;
	pseudoheader->lenght = icmp_ip.tot_len;
	icmp_udp->uh_sport = htons(cfg.icmp_ip_srcport);
	icmp_udp->uh_dport = htons(cfg.icmp_ip_dstport);
	icmp_udp->uh_ulen  = htons(UDPHDR_SIZE + udp_data_len);
	icmp_udp->uh_sum   = cksum((__u16 *) ph_buf, PSEUDOHDR_SIZE + UDPHDR_SIZE + udp_data_len);

	/* filling icmp body with concerned packet header.
	 * left_space starts at IPHDR_SIZE + UDPHDR_SIZE + data_size, so
	 * the quoted IP and UDP headers always fit: copy exactly the
	 * source header sizes (never more than the source objects). */

	/* fill IP */
	memcpy(packet+ICMPHDR_SIZE, &icmp_ip, IPHDR_SIZE);
	left_space -= IPHDR_SIZE;
	data += IPHDR_SIZE;

	/* fill UDP */
	memcpy(packet+ICMPHDR_SIZE+IPHDR_SIZE, icmp_udp, UDPHDR_SIZE);
	left_space -= UDPHDR_SIZE;
	data += UDPHDR_SIZE;

	/* fill DATA */
	if (left_space > 0)
		data_handler(data, left_space);

	/* icmp checksum */
	if (cfg.icmp_cksum == -1)
		icmp->checksum = cksum((u_short*)packet, ICMPHDR_SIZE + IPHDR_SIZE + UDPHDR_SIZE + cfg.data_size);
	else
		icmp->checksum = cfg.icmp_cksum;

	/* send packet */
	rc = send_ip_handler(packet, ICMPHDR_SIZE + IPHDR_SIZE + UDPHDR_SIZE + cfg.data_size);
	free (packet);
	free (ph_buf);
	return rc;
}
