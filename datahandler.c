/* 
 * $smu-mark$ 
 * $name: datahandler.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:47 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: datahandler.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <string.h>

#include "hping2.h"
#include "globals.h"

void data_handler(char *data, int size)
{
	if (cfg.opt_listenmode) { /* send an HCMP */
		memcpy(data, ctx.rsign, cfg.signlen); /* ok, write own reverse sign */
		data+=cfg.signlen;
		size-=cfg.signlen;
		memcpy(data, ctx.hcmphdr_p, size);
		return; /* done */
	}

	if (cfg.opt_sign) {
		memcpy(data, cfg.sign, cfg.signlen); /* lenght pre-checked */
		data+=cfg.signlen;
		size-=cfg.signlen;
	}

	if (size == 0)
		return; /* there is not space left */

	if (cfg.opt_datafromfile)
		datafiller(data, size);
	else
		memset(data, 'X', size);
}
