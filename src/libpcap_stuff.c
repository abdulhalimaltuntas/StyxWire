/*
 * $smu-mark$
 * $name: libpcap_stuff.c$
 * $author: Salvatore Sanfilippo <antirez@invece.org>$
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$
 * $license: This software is under GPL version 2 of license$
 * $date: Fri Nov  5 11:55:48 MET 1999$
 * $rev: 8$
 */

/* $Id: libpcap_stuff.c,v 1.3 2004/04/09 23:38:56 antirez Exp $ */

#include "hping2.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#ifdef HAVE_NET_BPF_H
#include <net/bpf.h>	/* BIOCIMMEDIATE on BSD systems */
#endif
#include <pcap.h>

#include "globals.h"

/* Open the capture handle on cfg.ifname.
 *
 * The handle is put in non blocking mode: the event loop (lifecycle.c)
 * waits on its selectable descriptor with poll(2) and then reads with
 * pcap_recv(), which returns 0 when nothing is queued. Immediate mode
 * (libpcap >= 1.5) delivers frames as soon as they arrive instead of
 * buffering them until the read timeout; on older libpcaps the BSD
 * BIOCIMMEDIATE ioctl does the same. */
int open_pcap()
{
	/* --read: dissect a pcap savefile instead of a live interface.
	 * No privileges, no traffic; the event loop reads it to EOF. The
	 * link-layer type comes from the file (get_linkhdr_size uses it). */
	if (cfg.readfile != NULL) {
		if (cfg.opt_debug)
			printf("DEBUG: pcap_open_offline(%s)\n", cfg.readfile);
		ctx.pcapfp = pcap_open_offline(cfg.readfile, ctx.errbuf);
		if (ctx.pcapfp == NULL) {
			fprintf(stderr, "[open_pcap] %s\n", ctx.errbuf);
			return -1;
		}
		/* a savefile has no selectable descriptor: the loop reads it
		 * without blocking (pcap_next_ex returns -2 at EOF) */
		ctx.pcap_fd = -1;
		ctx.pcap_poll_ms = 0;
		return 0;
	}

	if (cfg.opt_debug)
		printf("DEBUG: pcap_open(%s, 65535+link, no promisc, immediate)\n",
			cfg.ifname);

#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
	ctx.pcapfp = pcap_create(cfg.ifname, ctx.errbuf);
	if (ctx.pcapfp == NULL) {
		fprintf(stderr, "[open_pcap] pcap_create: %s\n", ctx.errbuf);
		return -1;
	}
	if (pcap_set_snaplen(ctx.pcapfp, 99999) != 0 ||
	    pcap_set_promisc(ctx.pcapfp, 0) != 0 ||
	    pcap_set_timeout(ctx.pcapfp, 1) != 0 ||
	    pcap_set_immediate_mode(ctx.pcapfp, 1) != 0) {
		fprintf(stderr, "[open_pcap] cannot configure the capture handle: %s\n",
			pcap_geterr(ctx.pcapfp));
		pcap_close(ctx.pcapfp);
		ctx.pcapfp = NULL;
		return -1;
	}
	{
		int rc = pcap_activate(ctx.pcapfp);
		if (rc < 0) {
			fprintf(stderr, "[open_pcap] pcap_activate: %s\n",
				pcap_geterr(ctx.pcapfp));
			pcap_close(ctx.pcapfp);
			ctx.pcapfp = NULL;
			return -1;
		}
		if (rc > 0 && cfg.opt_verbose)
			fprintf(stderr, "[open_pcap] warning: %s\n",
				pcap_geterr(ctx.pcapfp));
	}
#else
	ctx.pcapfp = pcap_open_live(cfg.ifname, 99999, 0, 1, ctx.errbuf);
	if (ctx.pcapfp == NULL) {
		fprintf(stderr, "[open_pcap] pcap_open_live: %s\n", ctx.errbuf);
		return -1;
	}
#ifdef BIOCIMMEDIATE
	{
		int on = 1;
		/* Return the packets to userspace as fast as possible */
		if (ioctl(pcap_fileno(ctx.pcapfp), BIOCIMMEDIATE, &on) == -1)
			perror("[open_pcap] ioctl(... BIOCIMMEDIATE ...)");
	}
#endif
#endif
	if (pcap_setnonblock(ctx.pcapfp, 1, ctx.errbuf) == -1) {
		fprintf(stderr, "[open_pcap] pcap_setnonblock: %s\n", ctx.errbuf);
		pcap_close(ctx.pcapfp);
		ctx.pcapfp = NULL;
		return -1;
	}
	ctx.pcap_fd = pcap_get_selectable_fd(ctx.pcapfp);
	ctx.pcap_poll_ms = 10;
#ifdef HAVE_PCAP_GET_REQUIRED_SELECT_TIMEOUT
	if (ctx.pcap_fd == -1) {
		const struct timeval *tv = pcap_get_required_select_timeout(ctx.pcapfp);
		if (tv != NULL) {
			long ms = tv->tv_sec * 1000 + tv->tv_usec / 1000;
			ctx.pcap_poll_ms = ms < 1 ? 1 : (ms > 1000 ? 1000 : (int) ms);
		}
	}
#endif
	if (cfg.opt_debug)
		printf("DEBUG: pcap selectable fd %d, poll period %d ms\n",
			ctx.pcap_fd, ctx.pcap_poll_ms);
	return 0;
}

int close_pcap()
{
	if (ctx.pcapfp != NULL)
		pcap_close(ctx.pcapfp);
	ctx.pcapfp = NULL;
	ctx.pcap_fd = -1;
	return 0;
}

/* Read the next captured frame into 'packet', which can hold 'size' bytes.
 *
 * Returns the number of bytes stored in 'packet': the captured length
 * (hdr.caplen) or 'size' when the frame is larger than the buffer, in
 * which case the frame is truncated (a debug message reports it).
 * Only the returned number of bytes are valid in 'packet'.
 * Returns 0 when no frame is available right now (non blocking handle,
 * or the read timeout expired), -1 on a capture error or at the end of a
 * savefile. */
int pcap_recv(char *packet, unsigned int size)
{
	const unsigned char *p = NULL;
	struct pcap_pkthdr *h = NULL;
	unsigned int pcapsize;
	int rc;

	if (ctx.pcapfp == NULL)
		return -1;
	rc = pcap_next_ex(ctx.pcapfp, &h, &p);
	if (rc == 0)
		return 0;
	if (rc != 1) {
		if (rc == -1)
			fprintf(stderr, "[pcap_recv] %s\n", pcap_geterr(ctx.pcapfp));
		return -1; /* error, or end of savefile */
	}
	ctx.hdr = *h;

	pcapsize = ctx.hdr.caplen;
	if (pcapsize > size) {
		if (cfg.opt_debug)
			printf("DEBUG: [pcap_recv] frame of %u bytes truncated "
			       "to %u\n", pcapsize, size);
		pcapsize = size;
	}
	memcpy(packet, p, pcapsize);
	return (int) pcapsize;
}
