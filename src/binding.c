/* 
 * $smu-mark$ 
 * $name: binding.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:46 MET 1999$ 
 * $rev: 11$ 
 */ 

/* $Id: binding.c,v 1.2 2003/09/01 00:15:22 antirez Exp $ */

#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#include "hping2.h"
#include "globals.h"

/* ctrl+z binding (--bind/--unbind): increment the destination port or
 * the TTL, decrement on a double press. Called by the event loop when
 * SIGTSTP was received, never from the handler itself. */
void inc_destparm(void)
{
	static long long last_us = 0;
	long long now_us;
	int *p;
	int errno_save = errno;

	switch (cfg.ctrlzbind) {
	case BIND_DPORT:
		p = &cfg.dst_port;
		break;
	case BIND_TTL:
		p = &cfg.src_ttl;
		break;
	default:
		printf("error binding ctrl+z\n");
		/* errno = errno_save; */
		return;
	}

	now_us = hping_monotonic_us();
	/* two presses within 200 ms decrement instead of increment */
	if (last_us != 0 && (now_us - last_us) < 200000) {
		if (*p > 0)
			(*p)-=2;
		if (*p < 0)
			*p=0;
	} else
		(*p)++;
	
	printf("\b\b\b\b\b\b\b\b\b");
	printf("%d: ", *p);
	fflush(stdout);

	last_us = now_us;
	errno = errno_save;
}
