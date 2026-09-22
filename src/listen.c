/* 
 * $smu-mark$ 
 * $name: listen.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:48 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: listen.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "hping2.h" /* hping2.h includes hcmp.h */
#include "globals.h"

/* --listen: print the data that follows the signature in every matching
 * packet. Runs until a stop is requested (SIGINT/SIGTERM, read error). */
int listen_run(void)
{
	int size, ip_size;
	int stdoutFD = fileno(stdout);
	char packet[IP_MAX_SIZE+ctx.linkhdr_size];
	char *p, *ip_packet;
	struct myiphdr ip;
	__u16 id;
	static __u16 exp_id; /* expected id */

	exp_id = 1;

	while(!hping_stop_requested()) {
		int r = ctx.io.wait(-1);
		if (r < 0) {
			perror("[listen] waiting for packets");
			hping_stop(HPING_STOP_ERROR);
			break;
		}
		if (r == 0)
			continue;
		size = read_packet(packet, IP_MAX_SIZE+ctx.linkhdr_size);
		switch(size) {
		case 0:
			continue;
		case -1:
			hping_stop(HPING_STOP_EOF);
			continue;
		}

		/* Skip truncated packets */
		if (size < (int)(ctx.linkhdr_size+IPHDR_SIZE))
			continue;

		ip_packet = packet + ctx.linkhdr_size;

		/* copy the ip header so it will be aligned */
		memcpy(&ip, ip_packet, sizeof(ip));
		id = ntohs(ip.id);
		ip_size = ntohs(ip.tot_len);
		if (size-(int)ctx.linkhdr_size > ip_size)
			size = ip_size;
		else
			size -= ctx.linkhdr_size;

		if ((p = memstr(ip_packet, cfg.sign, size))) {
			ssize_t w;

			if (cfg.opt_verbose)
				fprintf(stderr, "packet %d received\n", id);
			if (cfg.opt_safe) {
				if (id == exp_id)
					exp_id++;
				else {
					if (cfg.opt_verbose)
						fprintf(stderr, "packet not in sequence (id %d) received\n", id);
					send_hcmp(HCMP_RESTART, exp_id);
					if (cfg.opt_verbose)
						fprintf(stderr, "HCMP restart from %d sent\n", exp_id);
					continue; /* discard this packet */
				}
			}
			p+=strlen(cfg.sign);
			w = write(stdoutFD, p, size-(p-ip_packet));
			if (w == -1) {
				perror("[listen] write");
				hping_stop(HPING_STOP_ERROR);
			}
		}
	}
	return 0;
}
