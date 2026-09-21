/* 
 * $smu-mark$ 
 * $name: statistics.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:50 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: statistics.c,v 1.3 2004/04/09 23:38:56 antirez Exp $ */

#include <stdlib.h>
#include <stdio.h>

#include "hping2.h"
#include "globals.h"

void hping_stats_on_sent(void)
{
	stats.sent++;
}

/* A reply matched the target and the ports. 'status' tells what the
 * delay table knew about the probe: S_SENT (first answer), S_RECV (already
 * answered: a duplicate) or S_UNKNOWN (no entry: late reply, or the table
 * overflowed). */
void hping_stats_on_reply(int status)
{
	stats.received++;
	if (status == S_RECV)
		stats.duplicates++;
	else if (status == S_UNKNOWN)
		stats.unmatched++;
}

/* Running min/avg/max of the round trip time. Only replies whose probe
 * was found in the delay table produce a sample. */
void hping_stats_rtt_sample(float ms)
{
	if (stats.rtt_samples == 0 || ms < stats.rtt_min)
		stats.rtt_min = ms;
	if (stats.rtt_samples == 0 || ms > stats.rtt_max)
		stats.rtt_max = ms;
	stats.rtt_samples++;
	stats.rtt_avg += ((double) ms - stats.rtt_avg) / (double) stats.rtt_samples;
}

/* Replies that answered a distinct probe: neither a duplicate nor a reply
 * whose probe is unknown. */
unsigned long long hping_stats_unique(const struct hping_stats *s)
{
	unsigned long long other = s->duplicates + s->unmatched;

	return s->received > other ? s->received - other : 0;
}

/* Packet loss in percent, rounded down, based on unique replies:
 *   0 when nothing was sent (nothing could be lost),
 *   0 when every probe was answered (duplicates never make it negative),
 *   (sent - unique) * 100 / sent otherwise (like ping; the historical
 *   100 - received*100/sent rounded the other way: 2 of 3 gave 34%). */
int hping_stats_loss_percent(const struct hping_stats *s)
{
	unsigned long long unique = hping_stats_unique(s);

	if (s->sent == 0)
		return 0;
	if (unique >= s->sent)
		return 0;
	return (int) (((s->sent - unique) * 100) / s->sent);
}

void hping_stats_print(FILE *fp, const char *target)
{
	fprintf(fp, "\n--- %s hping statistic ---\n", target);
	fprintf(fp, "%llu packets transmitted, %llu packets received, "
		    "%d%% packet loss\n", stats.sent, stats.received,
		    hping_stats_loss_percent(&stats));
	if (stats.duplicates || stats.unmatched)
		fprintf(fp, "%llu duplicate and %llu unmatched replies\n",
			stats.duplicates, stats.unmatched);
	if (stats.out_of_sequence)
		fprintf(fp, "%llu out of sequence packets received\n",
			stats.out_of_sequence);
	fprintf(fp, "round-trip min/avg/max = %.1f/%.1f/%.1f ms\n",
		stats.rtt_min, stats.rtt_avg, stats.rtt_max);
}

/* The exit status contract: --tcpexitcode returns the flags of the last
 * TCP reply, otherwise 0 when at least one reply was received, 1 when
 * none. */
int hping_exit_code(void)
{
	if (cfg.opt_tcpexitcode)
		return ctx.tcp_exitcode;
	return stats.received ? 0 : 1;
}
