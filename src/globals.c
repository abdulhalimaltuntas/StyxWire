/* globals.c -- the three state objects of the command line tool and their
 * default values (see globals.h).
 *
 * Copyright (C) 1999 by Salvatore Sanfilippo (the defaults come from the
 * historical main.c), GPL version 2. */

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "hping2.h"
#include "globals.h"

struct hping_config cfg;
struct hping_context ctx;
struct hping_stats stats;

/* Command line defaults: what parse_options() starts from. */
void hping_config_init(struct hping_config *c)
{
	memset(c, 0, sizeof(*c));
	c->virtual_mtu	= DEFAULT_VIRTUAL_MTU;
	c->sending_wait	= DEFAULT_SENDINGWAIT;
	c->opt_gethost	= TRUE;
	c->opt_icmptype	= DEFAULT_ICMP_TYPE;
	c->opt_icmpcode	= DEFAULT_ICMP_CODE;
	c->cs_window	= DEFAULT_CS_WINDOW;
	c->cs_window_shift = DEFAULT_CS_WINDOW_SHIFT;
	c->cs_vector_len = DEFAULT_CS_VECTOR_LEN;
	c->src_ttl	= DEFAULT_TTL;
	c->src_id	= -1;			/* random */
	c->base_dst_port = DEFAULT_DPORT;
	c->dst_port	= DEFAULT_DPORT;
	c->initsport	= DEFAULT_INITSPORT;
	c->src_winsize	= DEFAULT_SRCWINSIZE;
	c->src_thoff	= (TCPHDR_SIZE >> 2);
	c->count	= DEFAULT_COUNT;
	c->ctrlzbind	= DEFAULT_BIND;
	c->icmp_ip_version = DEFAULT_ICMP_IP_VERSION;
	c->icmp_ip_ihl	= DEFAULT_ICMP_IP_IHL;
	c->icmp_ip_tos	= DEFAULT_ICMP_IP_TOS;
	c->icmp_ip_tot_len = DEFAULT_ICMP_IP_TOT_LEN;
	c->icmp_ip_id	= DEFAULT_ICMP_IP_ID;
	c->icmp_ip_protocol = DEFAULT_ICMP_IP_PROTOCOL;
	c->icmp_ip_srcport = DEFAULT_DPORT;
	c->icmp_ip_dstport = DEFAULT_DPORT;
	c->icmp_cksum	= DEFAULT_ICMP_CKSUM;
	c->raw_ip_protocol = DEFAULT_RAW_IP_PROTOCOL;
	c->opt_scanports = "";
	c->apd_send	= NULL;
}

/* Run time state before hping_init(): no resources are open. */
void hping_context_init(struct hping_context *x)
{
	int i;

	memset(x, 0, sizeof(*x));
	x->sockraw = -1;
	x->pcapfp = NULL;
	x->pcap_fd = -1;
	x->pcap_poll_ms = 10;
	x->wake_fd[0] = x->wake_fd[1] = -1;
	x->end_deadline_us = -1;
	for (i = 0; i < TABLESIZE; i++)
		x->delaytable[i].seq = -1;
	hping_clock_system(x);
}

void hping_stats_init(struct hping_stats *s)
{
	memset(s, 0, sizeof(*s));
}
