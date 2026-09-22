/* 
 * $smu-mark$ 
 * $name: getlhs.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:47 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: getlhs.c,v 1.5 2004/04/09 23:38:56 antirez Exp $ */

#include <string.h>

#include "hping2.h"
#include "globals.h"


/* Link-layer header size for a libpcap DLT.
 *
 * The value is the number of bytes before the IP header. Types marked
 * "fixture" below are exercised by the test-suite with a pcap savefile
 * (tests/linklayer.sh, tests/test_waitpacket.c); the others are declared from their
 * specification and are not verified here, which is why the support
 * matrix in docs/PLATFORMS.txt lists them separately. A type whose
 * header size is not fixed (802.11, radiotap and token ring, where it
 * depends on the frame) returns -1 instead of a guess: a wrong size
 * silently misparses every packet.
 *
 * Returns the size, or -1 when the type is not supported. */
int dltype_to_lhs(int dltype)
{
	switch(dltype) {
	case DLT_EN10MB:	/* fixture: Ethernet */
		return 14;
	case DLT_RAW:		/* fixture: raw IP, no link header */
		return 0;
	case DLT_NULL:		/* fixture: BSD loopback, 4 byte AF */
		return 4;
#ifdef DLT_LOOP
	case DLT_LOOP:		/* OpenBSD loopback, 4 byte AF (big endian) */
		return 4;
#endif
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:	/* fixture: Linux cooked capture v1 */
		return 16;
#endif
#ifdef DLT_LINUX_SLL2
	case DLT_LINUX_SLL2:	/* fixture: Linux cooked capture v2 ("any") */
		return 20;
#endif
	case DLT_PPP:
#ifdef DLT_PPP_SERIAL
	case DLT_PPP_SERIAL:
#endif
#ifdef DLT_C_HDLC
	case DLT_C_HDLC:
#endif
		return 4;
	case DLT_PPP_BSDOS:
		return 24;
	case DLT_SLIP:
	case DLT_SLIP_BSDOS:
		return 16;
	case DLT_FDDI:
		return 13;
	case DLT_ATM_RFC1483:
#ifdef DLT_CIP
	case DLT_CIP:
#endif
#ifdef DLT_ATM_CLIP
	case DLT_ATM_CLIP:
#endif
		return 8;
#ifdef DLT_LANE8023
	case DLT_LANE8023:	/* 2 byte LANE header + Ethernet header */
		return 16;
#endif
	default:
		/* includes DLT_IEEE802 (802.5 token ring, whose routing
		 * information field is 0 to 18 bytes long), DLT_IEEE802_11
		 * and the radiotap types: their header length is not fixed */
		return -1;
	}
}

/* Set ctx.linkhdr_size from the capture handle's link-layer type.
 * Returns 0, or -1 (with a diagnostic naming the type) when the type is
 * not supported. */
int get_linkhdr_size(char *ifname_unused)
{
	int dltype = pcap_datalink(ctx.pcapfp);
	int lhs = dltype_to_lhs(dltype);
	const char *name;

	(void) ifname_unused;
	if (cfg.opt_debug)
		printf("DEBUG: dltype is %d\n", dltype);
	if (lhs < 0) {
		name = pcap_datalink_val_to_name(dltype);
		fprintf(stderr, "styxwire: unsupported link layer type %s (%d)"
			" on this capture source;\n"
			"supported types are listed in docs/PLATFORMS.txt\n",
			name ? name : "unknown", dltype);
		return -1;
	}
	ctx.linkhdr_size = (unsigned int) lhs;
	return 0;
}
