/* Scanner mode for hping3
 * Copyright(C) 2003 Salvatore Sanfilippo
 * All rights reserved
 *
 * Design (phase 2 decision record, see docs/ASAMA2-RAPORU.md):
 *
 * The scanner used to fork: the child sent the probes, the parent read the
 * replies, and the two shared the port table through a SysV shared memory
 * segment without any synchronisation (the segment was also never
 * removed). It now runs inside the single event loop of lifecycle.c:
 * probes are sent when the sending deadline is due, replies are handled
 * when the capture descriptor is readable, so the port table has one
 * owner and no locking question, stop/cleanup follow the common
 * contract, and the whole scanner can be tested offline with a fake
 * clock (tests/test_scan.c).
 *
 * The probing algorithm is the historical one: every selected port is
 * probed up to opt_scan_probes times, one round at a time; after the
 * third round the scanner waits an average RTT between rounds; when a
 * round produced no reply while probing at full speed, or when the last
 * two retries come, the interval between probes grows tenfold.
 *
 * TODO (historical):
 * an application-level aware UDP scanner.
 * add ICMP handling in replies.
 * The algorithm is far from be optimal.
 * */

/* $Id: scan.c,v 1.3 2003/10/22 10:41:00 antirez Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <signal.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>

#include "hping2.h"
#include "globals.h"
#include "hstring.h"

#define MAXPORT 65535

int opt_scan_probes = 8;
float avrgms = 0;
int avrgcount = 0;

/* ---------------------------- data structures ----------------------------- */

struct portinfo {
	int active;	/* selected and not yet answered */
	int retry;	/* probes left */
	long long sent_us; /* monotonic time of the last probe */
};

/* The scanner state, one instance per run (scan_run()) */
struct scan_state {
	struct portinfo *pi;	/* MAXPORT+1 entries */
	int round;		/* 1 based round counter ("retry" historically) */
	int next_port;		/* next port to look at in this round */
	int probed_this_round;	/* probes sent in the current round */
	long long interval_us;	/* between probes; grows when slowing down */
	long long start_us;
	long long next_send_us;	/* deadline of the next probe */
	long long round_pause_until_us; /* -1: no pause pending */
	int finishing;		/* waiting the final second for late replies */
};

static struct scan_state *scan_cur; /* for scan_process_packet() callers */

/* -------------------------------- misc ----------------------------------- */
static char *tcp_strflags(char *s, unsigned int flags)
{
	char *ftab = "FSRPAUXY", *p = s;
	int bit = 0;

	memset(s, '.', 8);
	s[8] = '\0';
	while(bit < 8) {
		if (flags & (1 << bit))
			p[bit] = ftab[bit];
		bit++;
	}
	return s;
}

static char *port_to_name(int port)
{
	struct servent *se;

	se = getservbyport(htons(port), NULL);
	if (!se)
		return "";
	else
		return se->s_name;
}

/* ----------------------------- ports parsing ------------------------------ */
static int parse_ports(struct portinfo *pi, char *ports)
{
	char *args[32], *p = strdup(ports);
	int argc, j, i;

	if (!p) {
		fprintf(stderr, "Out of memory");
		return 1;
	}
	argc = strftok(",", p, args, 32);
	for (j = 0; j < argc; j++) {
		int neg = 0;
		char *a = args[j];

		/* ports negation */
		if (a[0] == '!') {
			neg = 1;
			a++;
		}
		/* range */
		if (strchr(a, '-')) {
			char *range[2];
			int low, high;

			if (strftok("-", a, range, 2) != 2 ||
			    !strisnum(range[0]) || !strisnum(range[1]))
				goto err; /* syntax error */
			low = strtol(range[0], NULL, 0);
			high = strtol(range[1], NULL, 0);
			if (low > high) {
				int t;
				t = high;
				high = low;
				low = t;
			}
			if (low < 0 || high > MAXPORT)
				goto err; /* out of range */
			for (i = low; i <= high; i++)
				pi[i].active = !neg;
		/* all the ports */
		} else if (!strcmp(a, "all")) {
			for (i = 0; i <= MAXPORT; i++)
				pi[i].active = !neg;
		/* /etc/services ports */
		} else if (!strcmp(a, "known")) {
			struct servent *se;
			setservent(0);
			while((se = getservent()) != NULL) {
				int port = ntohs(se->s_port);
				if (port < 0 || port > MAXPORT)
					continue;
				pi[port].active = !neg;
			}
		/* a single port */
		} else {
			int port;
			if (!strisnum(a))
				goto err; /* syntax error */
			port = strtol(a, NULL, 0);
			if (port < 0 || port > MAXPORT)
				goto err; /* syntax error */
			pi[port].active = !neg;
		}
	}
	free(p);
	return 0;
err:
	free(p);
	return 1;
}

/* -------------------------------- output ---------------------------------- */

/* Send the probe for 'port' */
static int scan_send_probe(struct scan_state *st, int port)
{
	st->pi[port].retry--;
	cfg.dst_port = port;
	st->pi[port].sent_us = hping_monotonic_us();
	st->probed_this_round++;
	return send_tcp();
}

/* Everything is answered or out of retries: report and stop. */
static void scan_finish_report(struct scan_state *st)
{
	int i;

	fprintf(stderr, "All replies received. Done.\n");
	printf("Not responding ports: ");
	for (i = 0; i <= MAXPORT; i++) {
		if (st->pi[i].active && !st->pi[i].retry)
			printf("(%d %.11s) ", i, port_to_name(i));
	}
	printf("\n");
	fflush(stdout);
}

/* A round is over: decide what happens before the next one. Returns 1
 * when the scan is complete (no port left to probe). */
static int scan_round_done(struct scan_state *st, long long now)
{
	int i, recvd = 0;

	for (i = 0; i <= MAXPORT; i++) {
		if (!st->pi[i].active && st->pi[i].retry)
			recvd++;
	}
	/* More to scan? */
	if (st->probed_this_round == 0) {
		/* nothing was probed in this round: every port either
		 * answered or ran out of retries. When nothing at all
		 * answered, give late replies one more second. */
		if (!recvd && !st->finishing) {
			st->finishing = 1;
			st->round_pause_until_us = now + 1000000LL;
			return 0;
		}
		return 1;
	}
	/* After the third round wait an average RTT (or one second) so
	 * that replies to this round can arrive */
	if (st->round >= 3) {
		if (cfg.opt_debug)
			printf("AVRGMS %f\n", avrgms);
		if (avrgms)
			st->round_pause_until_us = now + (long long)(avrgms * 1000);
		else
			st->round_pause_until_us = now + 1000000LL;
	}
	/* Are we sending too fast? */
	if ((!recvd && st->interval_us == 0 && (now - st->start_us) > 500000LL) ||
	    (opt_scan_probes - st->round) <= 2)
	{
		if (cfg.opt_debug)
			printf("SLOWING DOWN\n");
		st->interval_us *= 10;
		st->interval_us++;
	}
	st->round++;
	st->next_port = 0;
	st->probed_this_round = 0;
	return 0;
}

/* Advance the sending side: send the next due probe, or close the round.
 * Returns -1 on a send error, 1 when the scan is complete, 0 otherwise. */
static int scan_step(struct scan_state *st, long long now)
{
	if (st->round_pause_until_us != -1) {
		if (now < st->round_pause_until_us)
			return 0;
		st->round_pause_until_us = -1;
		if (st->finishing)
			return 1;
	}
	if (now < st->next_send_us)
		return 0;
	while (st->next_port <= MAXPORT) {
		int port = st->next_port++;
		if (st->pi[port].active && st->pi[port].retry) {
			if (scan_send_probe(st, port) == -1)
				return -1;
			st->next_send_us = now + st->interval_us;
			return 0;
		}
	}
	return scan_round_done(st, now);
}

/* When the loop may sleep until (-1: nothing scheduled) */
static long long scan_next_deadline(struct scan_state *st)
{
	if (st->round_pause_until_us != -1)
		return st->round_pause_until_us;
	return st->next_send_us;
}

/* -------------------------------- input  ---------------------------------- */

/* Handle one captured frame of 'len' bytes. Returns 1 if the frame was a
 * reply for one of the scanned ports (and the port table was updated),
 * 0 otherwise. Every header is copied out of the frame only after checking
 * that the captured data really contains it. */
static int scan_process_packet(struct portinfo *pi, const char *packet, int len)
{
	struct myiphdr ip;
	int iplen, iphdrlen;

	/* minimal sanity checks */
	if (len < 0 || (unsigned int) len < ctx.linkhdr_size)
		return 0;
	iplen = len - ctx.linkhdr_size;
	if (iplen < (int) sizeof(struct myiphdr))
		return 0;
	/* copy the ip header in an access-safe place */
	memcpy(&ip, packet+ctx.linkhdr_size, sizeof(ip));
	iphdrlen = ip.ihl << 2;
	/* bogus header length: shorter than the fixed header or
	 * longer than the captured datagram */
	if (iphdrlen < (int) sizeof(struct myiphdr) || iphdrlen > iplen)
		return 0;
	/* check if the dest IP matches */
	if (memcmp(&ip.daddr, &ctx.local.sin_addr, sizeof(ip.daddr)))
		return 0;
	/* check if the source IP matches */
	if (ip.protocol != IPPROTO_ICMP &&
	    memcmp(&ip.saddr, &ctx.remote.sin_addr, sizeof(ip.saddr)))
		return 0;
	if (ip.protocol == IPPROTO_TCP) {
		struct mytcphdr tcp;
		char flags[16];
		long long rttms;
		int sport;

		/* more sanity checks */
		if ((iplen - iphdrlen) < (int) sizeof(tcp))
			return 0;
		/* time to copy the TCP header in a safe place */
		memcpy(&tcp, packet+ctx.linkhdr_size+iphdrlen, sizeof(tcp));

		/* check if the TCP dest port matches */
		if (ntohs(tcp.th_dport) != cfg.initsport)
			return 0;
		sport = ntohs(tcp.th_sport);
		if (pi[sport].active == 0)
			return 0;

		/* Note that we don't care about a wrote RTT
		 * result due to resend on the same port. */
		rttms = (hping_monotonic_us() - pi[sport].sent_us) / 1000;

		avrgcount++;
		avrgms = (avrgms*(avrgcount-1)/avrgcount)+(rttms/avrgcount);

		tcp_strflags(flags, tcp.th_flags);
		if ((tcp.th_flags & TH_SYN) || cfg.opt_verbose) {
		printf("%5d %-11.11s: %s %3d %5d %5d %5d\n",
				sport,
				port_to_name(sport),
				flags,
				ip.ttl,
				ip.id,
				ntohs(tcp.th_win),
				iplen);
		fflush(stdout);
		}
		pi[sport].active = 0;
		return 1;
	} else if (ip.protocol == IPPROTO_ICMP) {
		struct myicmphdr icmp;
		struct myiphdr subip;
		struct mytcphdr subtcp;
		const unsigned char *p;
		int port;
		struct in_addr gwaddr;

		/* more sanity checks, we are only interested
		 * in ICMP quoting the original packet. */
		if ((iplen - iphdrlen) <
		    (int) (sizeof(icmp)+sizeof(subip)+sizeof(subtcp)))
			return 0;
		/* time to copy headers in a safe place */
		p = (const unsigned char*) packet+ctx.linkhdr_size+iphdrlen;
		memcpy(&icmp, p, sizeof(icmp));
		p += sizeof(icmp);
		memcpy(&subip, p, sizeof(subip));
		p += sizeof(subip);
		memcpy(&subtcp, p, sizeof(subtcp));

		/* Check if the ICMP quoted packet matches */
		/* check if the source IP matches */
		if (memcmp(&subip.saddr, &ctx.local.sin_addr, sizeof(subip.saddr)))
			return 0;
		/* check if the destination IP matches */
		if (memcmp(&subip.daddr, &ctx.remote.sin_addr, sizeof(subip.daddr)))
			return 0;
		/* check if the quoted TCP packet port matches */
		if (ntohs(subtcp.th_sport) != cfg.initsport)
			return 0;
		port = ntohs(subtcp.th_dport);
		if (pi[port].active == 0)
			return 0;
		pi[port].active = 0;
		memcpy(&gwaddr.s_addr, &ip.saddr, 4);
		printf("%5d:                      %3d %5d %5d   (ICMP %3d %3d from %s)\n",
				port,
				ip.ttl,
				iplen,
				ntohs(ip.id),
				icmp.type,
				icmp.code,
				inet_ntoa(gwaddr));
		return 1;
	}
	return 0;
}

/* One frame from the capture handle */
static void scan_read_reply(struct scan_state *st)
{
	char packet[IP_MAX_SIZE+ctx.linkhdr_size];
	int len;

	len = read_packet(packet, IP_MAX_SIZE+ctx.linkhdr_size);
	if (len == -1) {
		hping_stop(HPING_STOP_EOF);
		return;
	}
	if (len > 0)
		scan_process_packet(st->pi, packet, len);
}

/* ---------------------------------- main ---------------------------------- */

/* Prepare the port table from --scan. Returns 0, or -1 on a syntax
 * error. Exposed for the tests. */
int scan_setup(struct scan_state *st, char *ports)
{
	int i, n = 0;

	memset(st, 0, sizeof(*st));
	st->pi = calloc(MAXPORT + 1, sizeof(*st->pi));
	if (st->pi == NULL) {
		fprintf(stderr, "Unable to allocate the port table\n");
		return -1;
	}
	for (i = 0; i <= MAXPORT; i++)
		st->pi[i].retry = opt_scan_probes;
	if (parse_ports(st->pi, ports)) {
		fprintf(stderr, "Ports syntax error for scan mode\n");
		free(st->pi);
		st->pi = NULL;
		return -1;
	}
	for (i = 0; i <= MAXPORT; i++) {
		if (!st->pi[i].active)
			st->pi[i].retry = 0;
		n += st->pi[i].active;
	}
	st->round = 1;
	st->interval_us = hping_send_interval_us();
	st->round_pause_until_us = -1;
	return n;
}

int scan_run(void)
{
	struct scan_state st;
	int ports, rc = 0;

	ports = scan_setup(&st, cfg.opt_scanports);
	if (ports == -1)
		return 1;
	scan_cur = &st;
	fprintf(stderr, "%d ports to scan, use -V to see all the replies\n", ports);
	fprintf(stderr, "+----+-----------+---------+---+-----+-----+-----+\n");
	fprintf(stderr, "|port| serv name |  flags  |ttl| id  | win | len |\n");
	fprintf(stderr, "+----+-----------+---------+---+-----+-----+-----+\n");

	/* the reply matches the probe on the source port: keep it fixed */
	cfg.opt_keepstill = TRUE;
	st.start_us = hping_monotonic_us();
	st.next_send_us = st.start_us;

	while (!hping_stop_requested()) {
		long long now = hping_monotonic_us(), deadline, timeout;
		int r;

		r = scan_step(&st, now);
		if (r == -1) {
			hping_stop(HPING_STOP_ERROR);
			rc = 1;
			break;
		}
		if (r == 1) {
			scan_finish_report(&st);
			hping_stop(HPING_STOP_COUNT);
			break;
		}
		now = hping_monotonic_us();
		deadline = scan_next_deadline(&st);
		timeout = deadline - now;
		if (timeout < 0)
			timeout = 0;
		r = ctx.io.wait(timeout);
		if (r < 0) {
			perror("[scan] waiting for packets");
			hping_stop(HPING_STOP_ERROR);
			rc = 1;
			break;
		}
		if (r > 0)
			scan_read_reply(&st);
	}
	scan_cur = NULL;
	free(st.pi);
	return rc;
}
