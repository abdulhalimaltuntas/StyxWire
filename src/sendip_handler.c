/* 
 * $smu-mark$ 
 * $name: sendip_handler.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 3$ 
 */ 

/* $Id: sendip_handler.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <stdio.h>

#include "hping2.h"
#include "globals.h"

int send_ip_handler(char *packet, unsigned int size)
{
	int rc = 0;
	ctx.ip_optlen = ip_opt_build(ctx.ip_opt);

	if (!cfg.opt_fragment && (size+ctx.ip_optlen+20 >= ctx.h_if_mtu))
	{
		/* auto-activate fragmentation */
		cfg.virtual_mtu = ctx.h_if_mtu-20;
		cfg.virtual_mtu = cfg.virtual_mtu - (cfg.virtual_mtu % 8);
		cfg.opt_fragment = TRUE;
		cfg.opt_mf = cfg.opt_df = FALSE; /* deactivate incompatible options */
		if (cfg.opt_verbose || cfg.opt_debug)
			printf("auto-activate fragmentation, fragments size: %d\n", cfg.virtual_mtu);
	}

	if (!cfg.opt_fragment)
	{
		unsigned short fragment_flag = 0;

		if (cfg.opt_mf) fragment_flag |= MF; /* more fragments */
		if (cfg.opt_df) fragment_flag |= DF; /* dont fragment */
		rc = send_ip((char*)&ctx.local.sin_addr,
			(char*)&ctx.remote.sin_addr,
			packet, size, fragment_flag, cfg.ip_frag_offset,
			ctx.ip_opt, ctx.ip_optlen);
	}
	else
	{
		unsigned int remainder = size;
		int frag_offset = 0;

		while(1) {
			if (remainder <= cfg.virtual_mtu)
				break;

			send_ip((char*)&ctx.local.sin_addr,
				(char*)&ctx.remote.sin_addr,
				packet+frag_offset,
				cfg.virtual_mtu, MF, frag_offset,
				ctx.ip_opt, ctx.ip_optlen);

			remainder-=cfg.virtual_mtu;
			frag_offset+=cfg.virtual_mtu;
		}

		rc = send_ip((char*)&ctx.local.sin_addr,
			(char*)&ctx.remote.sin_addr,
			packet+frag_offset,
			remainder, NF, frag_offset,
			ctx.ip_opt, ctx.ip_optlen);
	}
	return rc;
}
