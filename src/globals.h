/*
 * $smu-mark$
 * $name: globals.h$
 * $author: Salvatore Sanfilippo <antirez@invece.org>$
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$
 * $license: This software is under GPL version 2 of license$
 * $date: Fri Nov  5 11:55:47 MET 1999$
 * $rev: 9$
 */

/* $Id: globals.h,v 1.3 2004/06/18 09:53:11 antirez Exp $ */

/*
 * The state of the command line tool lives in three objects, defined in
 * globals.c:
 *
 *   cfg    struct hping_config   what parse_options() produced (plus a few
 *                                values it adjusts at run time, marked
 *                                "runtime-adjusted" below)
 *   ctx    struct hping_context  resources and mutable run time state:
 *                                sockets, capture handle, addresses,
 *                                sequence numbers, the delay table
 *   stats  struct hping_stats    counters and round trip time figures
 *
 * Each has an *_init() function that restores the defaults, so that a test
 * can start from a clean state. The objects are still globals because most
 * of the historical code takes no context argument; passing them explicitly
 * is a later step, this split only fixes the responsibilities.
 */

#ifndef _GLOBALS_H
#define _GLOBALS_H

#include <stdio.h>
#include <sys/time.h>
#include <pcap.h>

struct hping_config {
	/* protocol fields */
	unsigned int	tcp_th_flags,
			ip_tos,
			set_seqnum,
			tcp_seqnum,
			set_ack,
			tcp_ack,
			virtual_mtu,		/* runtime-adjusted: auto fragmentation */
			ip_frag_offset,
			signlen,
			lsr_length,
			ssr_length;
	unsigned short int data_size;		/* set from signlen when 0 and --sign */

	/* modes and flags */
	int		sending_wait,
			opt_rawipmode,
			opt_icmpmode,
			opt_udpmode,
			opt_scanmode,
			opt_listenmode,
			opt_waitinusec,
			opt_numeric,
			opt_gethost,
			opt_quiet,
			opt_relid,
			opt_fragment,		/* runtime-adjusted: auto fragmentation */
			opt_df,			/* runtime-adjusted: auto fragmentation */
			opt_mf,			/* runtime-adjusted: auto fragmentation */
			opt_debug,
			opt_verbose,
			opt_winid_order,
			opt_keepstill,
			opt_datafromfile,
			opt_hexdump,
			opt_contdump,
			opt_sign,
			opt_safe,
			opt_end,
			opt_traceroute,
			opt_seqnum,
			opt_incdport,
			opt_force_incdport,
			opt_icmptype,
			opt_icmpcode,
			opt_rroute,		/* runtime-adjusted: cleared if no room */
			opt_tcpexitcode,
			opt_badcksum,
			opt_tr_keep_ttl,
			opt_tcp_timestamp,
			opt_clock_skew,
			cs_window,
			cs_window_shift,
			cs_vector_len,
			opt_tr_stop,
			opt_tr_no_rtt,
			opt_rand_dest,
			opt_rand_source,
			opt_lsrr,		/* runtime-adjusted: cleared if too long */
			opt_ssrr,		/* runtime-adjusted: cleared if too long */
			opt_beep,
			opt_flood,
			opt_dry_run,
			opt_json,
			opt_force_icmp;

	/* values with a run time life of their own, initialised from the
	 * command line: TTL grows in traceroute mode, the destination port
	 * with --incdport / ctrl+z, the IP id with --safe */
	int		src_ttl,		/* runtime-adjusted */
			src_id,			/* runtime-adjusted, -1 = random */
			base_dst_port,
			dst_port,		/* runtime-adjusted */
			initsport,		/* -1 = random, fixed at init */
			src_winsize,
			src_thoff,
			count,			/* -1 = forever */
			ctrlzbind;

	/* ICMP error quoting (--icmp-ip*) */
	int		icmp_ip_version,
			icmp_ip_ihl,
			icmp_ip_tos,
			icmp_ip_tot_len,
			icmp_ip_id,
			icmp_ip_protocol,
			icmp_ip_srcport,
			icmp_ip_dstport,
			icmp_cksum,		/* -1 = compute */
			raw_ip_protocol;

	/* strings */
	char		datafilename[1024],
			targetname[1024],
			ifname[1024],		/* -I; filled by get_if_name() otherwise */
			spoofaddr[1024],
			icmp_ip_srcip[1024],
			icmp_ip_dstip[1024],
			icmp_gwip[1024],
			sign[1024];
	char		*opt_scanports;		/* --scan argument (malloc'ed or "") */
	char		*apd_send;		/* --apd-send description (malloc'ed) */
	char		*readfile;		/* -r/--read pcap savefile (malloc'ed) */

	/* source routes (--lsrr/--ssrr), already in IP option format */
	unsigned char	lsr[255],
			ssr[255];

	/* --interval uX / --fast / --faster: the sending interval */
	struct itimerval usec_delay;
};

/* How the event loop waits for and reads captured frames. The defaults
 * poll the capture handle (lifecycle.c); tests install their own. */
struct hping_io_ops {
	/* wait up to timeout_us (-1: forever) for a frame or a wake up.
	 * Returns 1 when a frame can be read, 0 on timeout/wake up, -1 on
	 * error. */
	int (*wait)(long long timeout_us);
	/* read one frame into buf (like read_packet()): bytes, 0 = none
	 * available, -1 = error/end of input */
	int (*read)(char *buf, int size);
};

/* Why the run loop ended (ctx.stop_reason) */
#define HPING_STOP_NONE		0
#define HPING_STOP_SIGNAL	1	/* SIGINT / SIGTERM */
#define HPING_STOP_COUNT	2	/* --count probes answered */
#define HPING_STOP_SENT		3	/* --count probes sent, late reply timeout expired */
#define HPING_STOP_TRACEROUTE	4	/* --tr-stop condition */
#define HPING_STOP_EOF		5	/* capture input ended (savefile) */
#define HPING_STOP_ERROR	6	/* unrecoverable I/O error */

struct hping_context {
	/* platform I/O */
	int		sockraw;		/* raw socket, -1 when closed */
	pcap_t		*pcapfp;		/* capture handle, NULL when closed */
	char		errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr hdr;			/* header of the last captured frame */
	int		pcap_fd;		/* selectable descriptor of pcapfp, -1 if none */
	int		pcap_poll_ms;		/* polling period when pcap_fd == -1 */
	int		wake_fd[2];		/* signal wake up pipe (read, write), -1 if none */
	unsigned int	linkhdr_size,
			h_if_mtu;

	/* event loop (lifecycle.c) */
	struct hping_io_ops io;
	int		stop_reason;		/* HPING_STOP_* */
	int		signals_installed;
	long long	next_send_us;		/* deadline of the next probe */
	long long	end_deadline_us;	/* stop waiting for replies at, -1 = none */

	/* addresses */
	struct sockaddr_in icmp_ip_src, icmp_ip_dst, icmp_gw, local, remote;
	char		targetstraddr[1024],
			ifstraddr[1024],
			rsign[1024];		/* reverse signature (hping -> gniph) */

	/* per packet state */
	int		src_port,
			sequence,
			eof_reached,
			tcp_exitcode;		/* th_flags of the last reply */
	char		ip_opt[40];
	unsigned int	ip_optlen;
	struct hcmphdr	*hcmphdr_p;		/* send_hcmp() -> data_handler() */

	/* replies delay table */
	volatile struct delaytable_element delaytable[TABLESIZE];
	int		delaytable_index;

	/* time and randomness sources (clock.c) */
	struct hping_clock clock;
	struct hping_random random;
};

/* Counters (statistics.c). 64 bit: a flood or a long running session
 * exceeds 2^31 packets. "received" counts every reply matched to the
 * target/ports, "duplicates" those whose probe was already answered,
 * "unmatched" those with no probe left in the delay table (late replies,
 * table overflow); unique replies = received - duplicates - unmatched. */
struct hping_stats {
	unsigned long long sent,
			received,
			duplicates,
			unmatched,
			out_of_sequence;	/* --rel: id sequence check */
	unsigned long long rtt_samples;
	float		rtt_min,
			rtt_max;
	double		rtt_avg;
};

void	hping_stats_on_sent(void);
void	hping_stats_on_reply(int status);	/* S_SENT, S_RECV or S_UNKNOWN */
void	hping_stats_rtt_sample(float ms);
unsigned long long hping_stats_unique(const struct hping_stats *s);
int	hping_stats_loss_percent(const struct hping_stats *s);
void	hping_stats_print(FILE *fp, const char *target);
int	hping_exit_code(void);

extern struct hping_config cfg;
extern struct hping_context ctx;
extern struct hping_stats stats;

void hping_config_init(struct hping_config *c);
void hping_context_init(struct hping_context *x);
void hping_stats_init(struct hping_stats *s);
void hping_clock_system(struct hping_context *x);	/* clock.c */

#endif /* _GLOBALS_H */
