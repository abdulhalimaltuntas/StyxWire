/* Copyright (C) 2003 Salvatore Sanfilippo
 * All rights reserved
 * $Id: split.c,v 1.4 2003/09/07 11:21:18 antirez Exp $ */

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "ars.h"

/* The packet buffers handed to the splitter are not aligned (they often
 * start after a 14 byte Ethernet header), so header fields are always
 * read through memcpy()ed copies, never through a struct pointer into
 * the buffer. */
int ars_seems_ip(struct ars_iphdr *ip, size_t size)
{
	struct ars_iphdr h;

	if (size < sizeof(h))
		return 0;
	memcpy(&h, ip, sizeof(h));
	if (h.version == 4 &&
	    h.ihl >= 5 &&
	    (size_t)(h.ihl << 2) <= size &&
	    ars_check_ip_cksum(ip) == 1)
		return 1;
	return 0;
}

int ars_guess_ipoff(void *packet, size_t size, int *lhs)
{
	size_t orig_size = size;
	unsigned char *p = packet;

	while(1) {
		if (size < sizeof (struct ars_iphdr))
			break;
		if (ars_seems_ip((struct ars_iphdr*) p, size) == 0) {
			/* We may probably assume the link header size
			 * to be multiple of two */
			p++;
			size--;
			continue;
		}
		*lhs = orig_size - size;
		return -ARS_OK;
	}
	return -ARS_ERROR;
}

/* The caller guarantees that the whole header (ihl*4 bytes, ihl >= 5)
 * is present in the buffer. */
int ars_check_ip_cksum(struct ars_iphdr *ip)
{
	unsigned char hdr[60]; /* max IPv4 header */
	u_int16_t stored, computed;
	int ip_hdrsize;

	ip_hdrsize = (((unsigned char*)ip)[0] & 0x0f) << 2;
	if (ip_hdrsize < (int) sizeof(struct ars_iphdr))
		return 0;
	memcpy(hdr, ip, ip_hdrsize);
	memcpy(&stored, hdr + 10, 2);
	hdr[10] = hdr[11] = 0;
	computed = ars_cksum(hdr, ip_hdrsize);
	return (stored == computed);
}

/* 'size' covers the whole ICMP message (header + data), at least 4 bytes */
int ars_check_icmp_cksum(struct ars_icmphdr *icmp, size_t size)
{
	unsigned char *copy;
	u_int16_t stored, computed;

	if (size < 4)
		return 0;
	copy = malloc(size);
	if (copy == NULL)
		return 0;
	memcpy(copy, icmp, size);
	memcpy(&stored, copy + 2, 2);
	copy[2] = copy[3] = 0;
	computed = ars_cksum(copy, size);
	free(copy);
	return (stored == computed);
}

#define ARS_SPLIT_DONE		0
#define ARS_SPLIT_GET_IP	1
#define ARS_SPLIT_GET_IPOPT	2
#define ARS_SPLIT_GET_ICMP	3
#define ARS_SPLIT_GET_UDP	4
#define ARS_SPLIT_GET_TCP	5
#define ARS_SPLIT_GET_TCPOPT	6
#define ARS_SPLIT_GET_IGRP	7
#define ARS_SPLIT_GET_IGRPENTRY	8
#define ARS_SPLIT_GET_DATA	9
#define ARS_SPLIT_GET_IP6	10
#define ARS_SPLIT_GET_ICMP6	11

int ars_split_ip(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);
int ars_split_ipopt(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);
int ars_split_icmp(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);
int ars_split_udp(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);
int ars_split_tcp(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);
int ars_split_tcpopt(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);
int ars_split_igrp(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);
int ars_split_igrpentry(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);
int ars_split_data(struct ars_packet *pkt, void *packet, size_t size,
						int *state, int *len);

/* Take it in sync with ARS_SPLIT_* defines */
int (*ars_split_state_handler[])(struct ars_packet *pkt, void *packet,
				size_t size, int *state, int *len) =
{
	NULL,
	ars_split_ip,
	ars_split_ipopt,
	ars_split_icmp,
	ars_split_udp,
	ars_split_tcp,
	ars_split_tcpopt,
	ars_split_igrp,
	ars_split_igrpentry,
	ars_split_data,
	ars_split_ip6,
	ars_split_icmp6
};

int ars_split_packet(void *packet, size_t size, int ipoff, struct ars_packet *pkt)
{
	size_t offset = 0;
	int state = ARS_SPLIT_GET_IP;
	unsigned char *p = packet;

	/* User asks for IP offset auto detection */
	if (ipoff == -1 && ars_guess_ipoff(packet, size, &ipoff) != -ARS_OK) {
		ars_set_error(pkt, "IP offset autodetection failed");
		return -ARS_INVALID;
	}
	if (ipoff < 0 || (size_t) ipoff > size) {
		ars_set_error(pkt, "IP offset larger than the packet");
		return -ARS_INVALID;
	}
	offset += ipoff;
	size -= ipoff;

	/* The first layer is IPv4 or IPv6 depending on the version nibble
	 * of the first byte; anything else is dissected as IPv4 so that a
	 * malformed packet still produces the historical result. */
	if (size >= 1 && ((p[offset] >> 4) & 0xf) == 6)
		state = ARS_SPLIT_GET_IP6;

	/* Implemented as a finite state machine:
	 * every state is handled with a protocol specific function */
	while (state != ARS_SPLIT_DONE) {
		int error;
		int len = 0;

		error = ars_split_state_handler[state](pkt, p + offset,
						size, &state, &len);
		if (error != -ARS_OK)
			return error;
		/* put off the link layer padding. A tot_len smaller than
		 * the IP header just parsed is bogus: in that case only
		 * the header is taken, nothing follows. */
		if (pkt->p_layer_nr == 1 &&
		    pkt->p_layer[0].l_type == ARS_TYPE_IP) {
			struct ars_iphdr *ip =  pkt->p_layer[0].l_data;
			size_t totlen = ntohs(ip->tot_len);
			if (totlen < (size_t) len)
				totlen = len;
			size = MIN(size, totlen);
		}
		/* the same for IPv6: the datagram is 40 + payload_len */
		if (pkt->p_layer_nr == 1 &&
		    pkt->p_layer[0].l_type == ARS_TYPE_IP6) {
			struct ars_ip6hdr *ip6 = pkt->p_layer[0].l_data;
			size_t totlen = (size_t) ntohs(ip6->payload_len) + len;
			size = MIN(size, totlen);
		}
		offset += len;
		size -= len;
		/* Force the DONE state if we reached the end */
		if (size == 0)
			state = ARS_SPLIT_DONE;
	}
	return -ARS_OK;
}

/* Select the right state based on the IP protocol field */
void ars_ip_next_state(int ipproto, int *state)
{
	switch(ipproto) {
	case ARS_IPPROTO_IPIP:
		*state = ARS_SPLIT_GET_IP;
		break;
	case ARS_IPPROTO_ICMP:
		*state = ARS_SPLIT_GET_ICMP;
		break;
	case ARS_IPPROTO_TCP:
		*state = ARS_SPLIT_GET_TCP;
		break;
	case ARS_IPPROTO_UDP:
		*state = ARS_SPLIT_GET_UDP;
		break;
	case ARS_IPPROTO_IGRP:
		*state = ARS_SPLIT_GET_IGRP;
		break;
	default:
		*state = ARS_SPLIT_GET_DATA;
		break;
	}
}

/* Select the state for an IPv6 "next header" value. Extension headers are
 * not dissected in this slice: their bytes are kept as a DATA layer. */
static void ars_ip6_next_state(int nexthdr, int *state)
{
	if (ars_ip6_is_extension(nexthdr)) {
		*state = ARS_SPLIT_GET_DATA;
		return;
	}
	switch (nexthdr) {
	case ARS_IPPROTO_ICMPV6:	*state = ARS_SPLIT_GET_ICMP6; break;
	case ARS_IPPROTO_TCP:		*state = ARS_SPLIT_GET_TCP; break;
	case ARS_IPPROTO_UDP:		*state = ARS_SPLIT_GET_UDP; break;
	case ARS_IPPROTO_ICMP:		*state = ARS_SPLIT_GET_ICMP; break;
	case ARS_IPPROTO_IPV6:		*state = ARS_SPLIT_GET_IP6; break;
	case ARS_IPPROTO_IPIP:		*state = ARS_SPLIT_GET_IP; break;
	default:			*state = ARS_SPLIT_GET_DATA; break;
	}
}

/* IPv6 header: fixed 40 bytes, no options and no header checksum. */
int ars_split_ip6(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	struct ars_ip6hdr ip6, *newip6;
	int flags = 0;
	int ip6size = ARS_IP6HDR_SIZE;

	memset(&ip6, 0, sizeof(ip6));
	memcpy(&ip6, packet, MIN(size, sizeof(ip6)));

	if (size < ARS_IP6HDR_SIZE) {
		flags |= ARS_SPLIT_FTRUNC;
		ip6size = size;
	}
	if ((newip6 = ars_add_ip6hdr(pkt, 0)) == NULL)
		return -ARS_NOMEM;
	memcpy(newip6, packet, ip6size);
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);
	*len = ip6size;

	if (flags & ARS_SPLIT_FTRUNC) {
		*state = ARS_SPLIT_GET_DATA;
		return -ARS_OK;
	}
	ars_ip6_next_state(ip6.nexthdr, state);
	return -ARS_OK;
}

/* ICMPv6: the ICMPv4 layout, but the checksum covers the IPv6 pseudo
 * header, so it can only be verified with the IPv6 header at hand. */
int ars_split_icmp6(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	struct ars_icmphdr *newicmp;
	int flags = 0;
	int icmpsize = ARS_ICMP6HDR_SIZE;

	if (size < (size_t) icmpsize) {
		flags |= ARS_SPLIT_FTRUNC;
		icmpsize = size;
	} else {
		/* verify the checksum against the preceding IPv6 header:
		 * add the layer first (so the pseudo header sees the real
		 * upper-layer length), then compare and remove it. */
		int error;
		u_int16_t stored, computed = 0;

		error = ars_add_generic(pkt, size, ARS_TYPE_ICMP6);
		if (error != -ARS_OK)
			return error;
		newicmp = pkt->p_layer[pkt->p_layer_nr].l_data;
		memcpy(newicmp, packet, size);
		stored = newicmp->checksum;
		newicmp->checksum = 0;
		error = ars_ip6_pseudo_cksum(pkt, pkt->p_layer_nr,
					     ARS_IPPROTO_ICMPV6, &computed);
		if (error != -ARS_OK) {
			/* no IPv6 header before it: cannot verify */
			computed = stored;
		}
		if (stored != computed)
			flags |= ARS_SPLIT_FBADCKSUM;
		error = ars_remove_layer(pkt, pkt->p_layer_nr);
		if (error != ARS_OK)
			return error;
	}

	if ((newicmp = ars_add_icmp6hdr(pkt, 0)) == NULL)
		return -ARS_NOMEM;
	memcpy(newicmp, packet, icmpsize);
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);
	*len = icmpsize;
	*state = ARS_SPLIT_GET_DATA;
	return -ARS_OK;
}

int ars_split_ip(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	struct ars_iphdr ip, *newip;
	int flags = 0;
	int ipsize;

	memset(&ip, 0, sizeof(ip));
	memcpy(&ip, packet, MIN(size, sizeof(ip)));

	/* Check for bad header size and checksum */
	if (size < sizeof(struct ars_iphdr)) {
		flags |= ARS_SPLIT_FTRUNC;
		ipsize = size;
	} else if (ip.ihl < 5) {
		/* Header length field shorter than the fixed header:
		 * malformed. Take the fixed header, the rest is data. */
		flags |= ARS_SPLIT_FTRUNC|ARS_SPLIT_FBADCKSUM;
		ipsize = sizeof(struct ars_iphdr);
	} else {
		ipsize = ip.ihl << 2;
		if (size < (size_t) ipsize) {
			flags |= ARS_SPLIT_FTRUNC;
			ipsize = size;
		}
		else if (ars_check_ip_cksum(packet) == 0)
			flags |= ARS_SPLIT_FBADCKSUM;
		ipsize = MIN(ipsize, 20);
	}
	if ((newip = ars_add_iphdr(pkt, 0)) == NULL)
		return -ARS_NOMEM;

	memcpy(newip, packet, ipsize);
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);
	*len = ipsize;

	if (flags & ARS_SPLIT_FTRUNC) {
		*state = ARS_SPLIT_GET_DATA;
		return -ARS_OK;
	}

	if (ip.ihl > 5) { /* IP options */
		/* IP protocol saved so after the IP option
		 * processing we can start with the right status */
		pkt->aux_ipproto = ip.protocol;
		*state = ARS_SPLIT_GET_IPOPT;
		pkt->aux = (ip.ihl - 5) << 2;
		return -ARS_OK;
	}
	ars_ip_next_state(ip.protocol, state);
	return -ARS_OK;
}

int ars_split_ipopt(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	unsigned char *ipopt = packet; /* [0] = kind, [1] = len */
	int flags = 0;
	int optsize;
	int error;

	/* pkt->aux was set by ars_split_ip, or by ars_split_ipopt itself */
	size = MIN(size, pkt->aux);
	if (size == 0) {
		*len = 0;
		*state = ARS_SPLIT_GET_DATA;
		return -ARS_OK;
	}

	if (ipopt[0] == ARS_IPOPT_END || ipopt[0] == ARS_IPOPT_NOOP)
		optsize = 1;
	else if (size < 2) {
		optsize = 1; /* the length byte is missing: truncated */
		flags |= ARS_SPLIT_FTRUNC;
	} else
		optsize = ipopt[1];

	/* Avoid infinite loop with broken packets */
	if (optsize == 0)
		optsize = 1;

	if (size < optsize) {
		flags |= ARS_SPLIT_FTRUNC;
		optsize = size;
	}

	pkt->aux -= optsize;
	error = ars_add_generic(pkt, optsize, ARS_TYPE_IPOPT);
	if (error != -ARS_OK)
		return error;
	memcpy(pkt->p_layer[pkt->p_layer_nr].l_data, ipopt, optsize);
	pkt->p_layer_nr++;
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);

	*len = optsize;

	if (pkt->aux > 0) {
		*state = ARS_SPLIT_GET_IPOPT;
	} else {
		ars_ip_next_state(pkt->aux_ipproto, state);
	}
	return -ARS_OK;
}

int ars_split_icmp(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	struct ars_icmphdr icmp, *newicmp;
	int flags = 0;
	int icmpsize = ARS_ICMPHDR_SIZE;

	memset(&icmp, 0, sizeof(icmp));
	memcpy(&icmp, packet, MIN(size, sizeof(icmp)));

	/* Check for bad header size and checksum */
	if (size < (size_t) icmpsize) {
		flags |= ARS_SPLIT_FTRUNC;
		icmpsize = size;
	}
	else if (ars_check_icmp_cksum(packet, size) == 0)
		flags |= ARS_SPLIT_FBADCKSUM;

	if ((newicmp = ars_add_icmphdr(pkt, 0)) == NULL)
		return -ARS_NOMEM;
	memcpy(newicmp, packet, icmpsize);
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);

	*len = icmpsize;

	if (flags & ARS_SPLIT_FTRUNC) {
		*state = ARS_SPLIT_GET_DATA;
		return -ARS_OK;
	}

	switch(icmp.type) {
	case ARS_ICMP_ECHO:
	case ARS_ICMP_ECHOREPLY:
	case ARS_ICMP_TIMESTAMP:
	case ARS_ICMP_TIMESTAMPREPLY:
	case ARS_ICMP_INFO_REQUEST:
	case ARS_ICMP_INFO_REPLY:
		*state = ARS_SPLIT_GET_DATA;
		break;
	default:
		*state = ARS_SPLIT_GET_IP;
		break;
	}
	return -ARS_OK;
}

int ars_split_data(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	void *newdata;

	if ((newdata = ars_add_data(pkt, size)) == NULL)
		return -ARS_NOMEM;
	memcpy(newdata, packet, size);

	*len = size;

	*state = ARS_SPLIT_DONE;
	return -ARS_OK;
}

int ars_split_udp(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	struct ars_udphdr udp, *newudp;
	int flags = 0;
	int udpsize = ARS_UDPHDR_SIZE;
	int error;
	u_int16_t udpcksum = 0;

	memset(&udp, 0, sizeof(udp));
	memcpy(&udp, packet, MIN(size, sizeof(udp)));

	/* Check for bad header size: with a truncated header there is
	 * nothing to verify, so the checksum hack below is skipped
	 * (it would write past the temporary layer). */
	if (size < (size_t) udpsize) {
		flags |= ARS_SPLIT_FTRUNC;
		udpsize = size;
	} else {
		/* XXX hack, we need to add a temp unusual layer
		 * (UDP+UDP_DATA) to use the ars_udptcp_cksum() function. */

		/* --- HACK START --- */
		error = ars_add_generic(pkt, size, ARS_TYPE_UDP);
		if (error != -ARS_OK)
			return error;
		newudp = pkt->p_layer[pkt->p_layer_nr].l_data;
		memcpy(newudp, packet, size);
		newudp->uh_sum = 0;
		error = ars_udptcp_cksum(pkt, pkt->p_layer_nr, &udpcksum);
		if (error != ARS_OK) {
			pkt->p_layer_nr++; /* just to be sane */
			return error;
		}
		error = ars_remove_layer(pkt, pkt->p_layer_nr);
		if (error != ARS_OK)
			return error;
		/* --- HACK END --- */

		if (udp.uh_sum != udpcksum)
			flags |= ARS_SPLIT_FBADCKSUM;
	}

	if ((newudp = ars_add_udphdr(pkt, 0)) == NULL)
		return -ARS_NOMEM;
	memcpy(newudp, packet, udpsize);
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);

	*len = udpsize;
	*state = ARS_SPLIT_GET_DATA;
	return -ARS_OK;
}

int ars_split_tcp(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	struct ars_tcphdr tcp, *newtcp;
	int flags = 0;
	int tcpsize;
	int error;
	u_int16_t tcpcksum = 0;

	/* The fixed header must be there before any field is read */
	if (size < ARS_TCPHDR_SIZE) {
		flags |= ARS_SPLIT_FTRUNC;
		tcpsize = size;
		if ((newtcp = ars_add_tcphdr(pkt, 0)) == NULL)
			return -ARS_NOMEM;
		memcpy(newtcp, packet, tcpsize);
		ars_set_flags(pkt, ARS_LAST_LAYER, flags);
		*len = tcpsize;
		*state = ARS_SPLIT_GET_DATA;
		return -ARS_OK;
	}
	memcpy(&tcp, packet, sizeof(tcp));
	tcpsize = tcp.th_off << 2;

	/* XXX hack, we need to add a temp unusual layer (TCP+TCP_DATA) to
	 * use the ars_udptcp_cksum() function. */

	/* --- HACK START --- */
	error = ars_add_generic(pkt, size, ARS_TYPE_TCP);
	if (error != -ARS_OK)
		return error;
	newtcp = pkt->p_layer[pkt->p_layer_nr].l_data;
	memcpy(newtcp, packet, size);
	newtcp->th_sum = 0;
	error = ars_udptcp_cksum(pkt, pkt->p_layer_nr, &tcpcksum);
	if (error != ARS_OK) {
		pkt->p_layer_nr++; /* just to be sane */
		return error;
	}
	error = ars_remove_layer(pkt, pkt->p_layer_nr);
	if (error != ARS_OK)
		return error;
	/* --- HACK END --- */

	/* Check for bad header size and checksum. A data offset smaller
	 * than the fixed header is malformed: the fixed header is taken
	 * and what follows is data. */
	if (tcp.th_off < 5) {
		flags |= ARS_SPLIT_FBADCKSUM;
		tcpsize = ARS_TCPHDR_SIZE;
	} else if (size < (size_t) tcpsize) {
		flags |= ARS_SPLIT_FTRUNC;
		tcpsize = size;
	}
	else if (tcp.th_sum != tcpcksum)
		flags |= ARS_SPLIT_FBADCKSUM;

	tcpsize = MIN(tcpsize, 20);

	if ((newtcp = ars_add_tcphdr(pkt, 0)) == NULL)
		return -ARS_NOMEM;
	memcpy(newtcp, packet, tcpsize);
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);

	*len = tcpsize;
	if (tcp.th_off > 5) {
		*state = ARS_SPLIT_GET_TCPOPT;
		pkt->aux = (tcp.th_off - 5) << 2;
	} else {
		*state = ARS_SPLIT_GET_DATA;
	}
	return -ARS_OK;
}

int ars_split_tcpopt(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	unsigned char *tcpopt = packet; /* [0] = kind, [1] = len */
	int flags = 0;
	int optsize;
	int error;

	/* pkt->aux was set by ars_split_tcp, or by ars_split_tcpopt itself */
	size = MIN(size, pkt->aux);
	if (size == 0) {
		*len = 0;
		*state = ARS_SPLIT_GET_DATA;
		return -ARS_OK;
	}

	if (tcpopt[0] == ARS_TCPOPT_EOL || tcpopt[0] == ARS_TCPOPT_NOP)
		optsize = 1;
	else if (size < 2) {
		optsize = 1; /* the length byte is missing: truncated */
		flags |= ARS_SPLIT_FTRUNC;
	} else
		optsize = tcpopt[1];

	/* Avoid infinite loop with broken packets */
	if (optsize == 0)
		optsize = 1;

	if (size < optsize) {
		flags |= ARS_SPLIT_FTRUNC;
		optsize = size;
	}

	pkt->aux -= optsize;
	error = ars_add_generic(pkt, optsize, ARS_TYPE_TCPOPT);
	if (error != -ARS_OK)
		return error;
	memcpy(pkt->p_layer[pkt->p_layer_nr].l_data, tcpopt, optsize);
	pkt->p_layer_nr++;
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);

	*len = optsize;

	if (pkt->aux > 0)
		*state = ARS_SPLIT_GET_TCPOPT;
	else
		*state = ARS_SPLIT_GET_DATA;

	return -ARS_OK;
}

/* XXX: check for valid IGRP checksum */
int ars_split_igrp(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	int flags = 0, igrpsize = sizeof(struct ars_igrphdr);
	int error;

	if (size < sizeof(struct ars_igrphdr)) {
		flags |= ARS_SPLIT_FTRUNC;
		igrpsize = size;
	}
	error = ars_add_generic(pkt, sizeof(struct ars_igrphdr), ARS_TYPE_IGRP);
	if (error != -ARS_OK)
		return error;
	memcpy(pkt->p_layer[pkt->p_layer_nr].l_data, packet, igrpsize);
	pkt->p_layer_nr++;
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);
	*len = igrpsize;
	*state = ARS_SPLIT_GET_IGRPENTRY;
	return -ARS_OK;
}

int ars_split_igrpentry(struct ars_packet *pkt, void *packet, size_t size, int *state, int *len)
{
	int flags = 0, entrysize = sizeof(struct ars_igrpentry);
	int error;

	if (size < sizeof(struct ars_igrpentry)) {
		flags |= ARS_SPLIT_FTRUNC;
		entrysize = size;
	}
	error = ars_add_generic(pkt, sizeof(struct ars_igrpentry), ARS_TYPE_IGRPENTRY);
	if (error != -ARS_OK)
		return error;
	memcpy(pkt->p_layer[pkt->p_layer_nr].l_data, packet, entrysize);
	pkt->p_layer_nr++;
	ars_set_flags(pkt, ARS_LAST_LAYER, flags);
	*len = entrysize;
	*state = ARS_SPLIT_GET_IGRPENTRY;
	return -ARS_OK;
}
