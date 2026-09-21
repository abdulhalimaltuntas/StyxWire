/* 
 * $smu-mark$ 
 * $name: rtt.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 3$ 
 */ 

/* $Id: rtt.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <time.h>
#include <stdio.h>

#include "hping2.h"
#include "globals.h"

int rtt(int *seqp, int recvport, float *ms_delay)
{
	int i, tablepos = -1, status;

	if (*seqp != 0) {
		for (i = 0; i < TABLESIZE; i++)
			if (ctx.delaytable[i].seq == *seqp) {
				tablepos = i;
				break;
			}
	} else {
		for (i=0; i<TABLESIZE; i++)
			if (ctx.delaytable[i].src == recvport) {
				tablepos = i;
				break;
			}
		if (i != TABLESIZE)
			*seqp = ctx.delaytable[i].seq;
	}

	if (tablepos != -1)
	{
		long long elapsed_us;

		status = ctx.delaytable[tablepos].status;
		ctx.delaytable[tablepos].status = S_RECV;

		/* both timestamps come from the monotonic clock: the
		 * difference cannot be negative unless the clock source
		 * was replaced with a broken one */
		elapsed_us = hping_monotonic_us() - ctx.delaytable[tablepos].sent_us;
		if (elapsed_us < 0)
			elapsed_us = 0;
		*ms_delay = (float) elapsed_us / 1000;
		hping_stats_rtt_sample(*ms_delay);
	}
	else
	{
		*ms_delay = 0;	/* not in table.. */
		status = S_UNKNOWN;	/* late reply or table overflow */
	}

	return status;
}

/* Record a sent packet: the timestamp is taken here, from the
 * monotonic clock, so that a single clock read covers the whole entry. */
void delaytable_add(int seq, int src, int status)
{
	int slot = ctx.delaytable_index % TABLESIZE;

	ctx.delaytable[slot].seq = seq;
	ctx.delaytable[slot].src = src;
	ctx.delaytable[slot].sent_us = hping_monotonic_us();
	ctx.delaytable[slot].status = status;
	ctx.delaytable_index++;
}
