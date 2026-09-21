/* 
 * $smu-mark$ 
 * $name: sendudp.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: send.c,v 1.1.1.1 2003/08/31 17:23:53 antirez Exp $ */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

#include "hping2.h"
#include "globals.h"

static void select_next_random_source(void)
{
	unsigned char ra[4];

	ra[0] = hp_rand() & 0xFF;
	ra[1] = hp_rand() & 0xFF;
	ra[2] = hp_rand() & 0xFF;
	ra[3] = hp_rand() & 0xFF;
	memcpy(&ctx.local.sin_addr.s_addr, ra, 4);

	if (cfg.opt_debug)
		printf("DEBUG: the source address is %u.%u.%u.%u\n",
		    ra[0], ra[1], ra[2], ra[3]);
}

/* Convert one --rand-dest octet: "x" means random, otherwise a number
 * in the range 0-255. Returns -1 on a bad octet. */
static int rand_dest_octet(const char *s)
{
	char *end;
	unsigned long v;

	if (s[0] == 'x' && s[1] == '\0')
		return hp_rand() & 0xFF;
	if (s[0] == '\0')
		return -1;
	v = strtoul(s, &end, 10);
	if (*end != '\0' || v > 255)
		return -1;
	return (int) v;
}

/* Parse a --rand-dest template like "192.168.x.x" into 'ra'.
 * Returns 0 on success, -1 on error. Exported for the test-suite. */
int parse_rand_dest(const char *template, unsigned char ra[4])
{
	/* four octets of up to 4 chars each (sscanf adds the nul term) */
	char a[5], b[5], c[5], d[5];
	int v[4], i;
	const char *oct[4];

	if (sscanf(template, "%4[^.].%4[^.].%4[^.].%4[^.]", a, b, c, d) != 4)
		return -1;
	oct[0] = a; oct[1] = b; oct[2] = c; oct[3] = d;
	for (i = 0; i < 4; i++) {
		v[i] = rand_dest_octet(oct[i]);
		if (v[i] < 0)
			return -1;
	}
	for (i = 0; i < 4; i++)
		ra[i] = (unsigned char) v[i];
	return 0;
}

static int select_next_random_dest(void)
{
	unsigned char ra[4];

	if (parse_rand_dest(cfg.targetname, ra) == -1)
	{
		/* parse_options() validates the template, this is a guard */
		fprintf(stderr,
			"wrong --rand-dest target host, correct examples:\n"
			"  x.x.x.x, 192.168.x.x, 128.x.x.255\n"
			"you typed: %s\n", cfg.targetname);
		return -1;
	}
	memcpy(&ctx.remote.sin_addr.s_addr, ra, 4);

	if (cfg.opt_debug) {
		printf("DEBUG: the dest address is %u.%u.%u.%u\n",
				ra[0], ra[1], ra[2], ra[3]);
	}
	return 0;
}

/* Send one probe of the selected mode. Called from the event loop
 * (lifecycle.c) when the sending deadline is due, never from a signal
 * handler. Returns 0, or -1 when the packet could not be sent. */
int send_packet(void)
{
	int rc;

	if (cfg.opt_rand_dest && select_next_random_dest() == -1)
		return -1;
	if (cfg.opt_rand_source)
		select_next_random_source();

	if (cfg.opt_rawipmode)		rc = send_rawip();
	else if (cfg.opt_icmpmode)	rc = send_icmp();
	else if (cfg.opt_udpmode)	rc = send_udp();
	else				rc = send_tcp();

	if (rc == 0)
		hping_stats_on_sent();
	return rc;
}
