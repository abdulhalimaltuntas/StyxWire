/* test_waitpacket.c -- regression tests for the receive path (waitpacket.c).
 *
 * waitpacket.c is #included so that its static parsers can be driven
 * directly with crafted buffers. wait_packet() itself is exercised with a
 * pcap savefile: no interface is opened. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "waitpacket.c"
#include "testutil.h"

#define SADDR 0xc0a80106UL /* 192.168.1.6: "remote" */
#define DADDR 0xc0a80107UL /* 192.168.1.7: "local"  */

static void test_icmp_unreach_rtt(void)
{
	unsigned char q[64];
	int seq = 0, i, r;
	float ms;

	cfg.opt_tr_no_rtt = FALSE;
	memset(q, 0, sizeof(q));
	tu_build_ip(q, 0, 40, 6, DADDR, SADDR);	/* quoted: local -> remote, TCP */
	tu_build_tcp(q + 20, 4321, 80, 0x02, 5);

	TEST("icmp_unreach_rtt: quoted TCP header shorter than 8 bytes");
	/* Regression: after checking for 2 bytes, the whole 8 byte UDP
	 * header was copied out of the quote (6 bytes over-read). */
	for (i = 2; i < 8; i++) {
		seq = 0;
		r = icmp_unreach_rtt(q, 20 + i, &seq, &ms);
		CHECK(r == -1 || r == 0 || r == 1); /* no crash: not in delaytable */
	}
	CHECK_EQ_INT(icmp_unreach_rtt(q, 21, &seq, &ms), -1); /* 1 byte: too short */
	CHECK_EQ_INT(icmp_unreach_rtt(q, 19, &seq, &ms), -1); /* no IP header */

	TEST("icmp_unreach_rtt: quoted TCP source port is matched in the delaytable");
	delaytable_add(7, 4321, S_SENT);
	seq = 0;
	r = icmp_unreach_rtt(q, 22, &seq, &ms);	/* only the 2 port bytes */
	CHECK_EQ_INT(r, S_SENT);
	CHECK_EQ_INT(seq, 7);

	TEST("icmp_unreach_rtt: quoted ICMP header copied before its size was checked");
	memset(q, 0, sizeof(q));
	tu_build_ip(q, 0, 28, 1, DADDR, SADDR);
	q[20] = ICMP_ECHO;
	{
		/* hping puts the echo sequence on the wire in host order */
		__u16 s16 = 3;
		memcpy(q + 26, &s16, 2);
	}
	for (i = 0; i < 8; i++)
		CHECK_EQ_INT(icmp_unreach_rtt(q, 20 + i, &seq, &ms), -1);
	delaytable_add(3, 0, S_SENT);
	seq = 0;
	CHECK_EQ_INT(icmp_unreach_rtt(q, 28, &seq, &ms), S_SENT);

	TEST("icmp_unreach_rtt: quoted IP header with IHL < 5 is rejected");
	q[0] = 0x41;
	CHECK_EQ_INT(icmp_unreach_rtt(q, 28, &seq, &ms), -1);

	TEST("icmp_unreach_rtt: quoted IHL larger than the quote");
	q[0] = 0x4f; /* 60 byte header claimed, 28 present */
	CHECK_EQ_INT(icmp_unreach_rtt(q, 28, &seq, &ms), -1);
}

static void test_print_tcp_timestamp(void)
{
	unsigned char t[64];

	cfg.opt_clock_skew = FALSE;

	TEST("print_tcp_timestamp: zero-length option terminates");
	/* Regression: an option with len 0 never advanced the loop
	 * (infinite loop), and the header-length check was inverted so a
	 * data offset larger than the captured data walked past the buffer. */
	memset(t, 0, sizeof(t));
	tu_build_tcp(t, 80, 4321, 0x12, 8);	/* 12 bytes of options */
	t[20] = 2; t[21] = 0;			/* mss, len 0 */
	print_tcp_timestamp(t, 32, 1);
	CHECK(1); /* reached: no hang */
	t[20] = 2; t[21] = 1;			/* len 1: also never progresses */
	print_tcp_timestamp(t, 32, 1);
	CHECK(1);

	TEST("print_tcp_timestamp: data offset beyond the captured segment");
	memset(t, 0, sizeof(t));
	tu_build_tcp(t, 80, 4321, 0x12, 15);	/* claims 60 bytes */
	t[20] = 8; t[21] = 10;			/* a timestamp option, then garbage */
	print_tcp_timestamp(t, 24, 1);		/* only 24 captured */
	CHECK(1);
	print_tcp_timestamp(t, 19, 1);
	CHECK(1);

	TEST("print_tcp_timestamp: timestamp found after a payload-bearing header");
	/* Regression: the inverted check also returned early for every
	 * segment carrying data (tcphdrlen < tcpsize), so timestamps were
	 * never shown for such segments. */
	{
		FILE *tmp = tmpfile();
		int saved = dup(1);
		char out[256];
		size_t n;

		memset(t, 0, sizeof(t));
		tu_build_tcp(t, 80, 4321, 0x18, 8);
		t[20] = 1; t[21] = 1; t[22] = 8; t[23] = 10;
		tu_put32(t+24, 123456);
		tu_put32(t+28, 0);
		memset(t+32, 'd', 16);		/* 16 bytes of data */
		fflush(stdout);
		dup2(fileno(tmp), 1);
		print_tcp_timestamp(t, 48, 1);
		fflush(stdout);
		dup2(saved, 1);
		close(saved);
		rewind(tmp);
		n = fread(out, 1, sizeof(out)-1, tmp);
		out[n] = '\0';
		fclose(tmp);
		CHECK(strstr(out, "TCP timestamp: tcpts=123456") != NULL);
	}
}

static void test_handle_hcmp(void)
{
	char pkt[64];

	TEST("handle_hcmp: signature at the end of the packet");
	/* Regression: the remaining length was computed as
	 * size-(packet-p) (sign reversed), which is always larger than the
	 * packet, so the HCMP header was read past the buffer. */
	cfg.opt_sign = TRUE;
	cfg.opt_debug = FALSE; cfg.opt_verbose = FALSE;
	strcpy(ctx.rsign, "GNIS");
	memset(pkt, 0, sizeof(pkt));
	memcpy(pkt + 20, "GNIS", 4);
	handle_hcmp(pkt, 24);		/* signature ends exactly at the end */
	CHECK(1);
	handle_hcmp(pkt, 26);		/* 2 bytes after: header needs 8 */
	CHECK(1);
	/* a complete HCMP_SOURCE_QUENCH is still handled */
	pkt[24] = HCMP_SOURCE_QUENCH;
	{
		FILE *tmp = tmpfile();
		int saved = dup(1);
		char out[128];
		size_t n;
		fflush(stdout);
		dup2(fileno(tmp), 1);
		handle_hcmp(pkt, 32);
		fflush(stdout);
		dup2(saved, 1);
		close(saved);
		rewind(tmp);
		n = fread(out, 1, sizeof(out)-1, tmp);
		out[n] = '\0';
		fclose(tmp);
		CHECK(strstr(out, "HCMP source quench") != NULL);
	}
	cfg.opt_sign = FALSE;
}

/* wait_packet() end to end with a savefile: a TCP SYN+ACK reply for a
 * probe in the delaytable must be counted as received. */
static void test_wait_packet_savefile(void)
{
	unsigned char frame[14 + 60];
	unsigned short ck;
	char path[128];
	char err[PCAP_ERRBUF_SIZE];
	pcap_t *dead;
	pcap_dumper_t *dump;
	struct pcap_pkthdr h;
	int hlen;

	TEST("wait_packet: SYN+ACK reply from a savefile is matched");
	memset(frame, 0, sizeof(frame));
	frame[12] = 0x08; frame[13] = 0x00;		/* ethertype IP */
	hlen = tu_build_ip(frame + 14, 0, 40, 6, SADDR, DADDR);
	tu_build_tcp(frame + 14 + hlen, 80, 4321, 0x12, 5);
	ck = tu_l4_cksum(SADDR, DADDR, 6, frame + 14 + hlen, 20);
	memcpy(frame + 14 + hlen + 16, &ck, 2);

	snprintf(path, sizeof(path), "/tmp/hping-test-wp-%ld.pcap", (long)getpid());
	dead = pcap_open_dead(DLT_EN10MB, 65535);
	dump = pcap_dump_open(dead, path);
	CHECK(dump != NULL);
	if (!dump) return;
	memset(&h, 0, sizeof(h));
	h.caplen = h.len = 14 + 40;
	pcap_dump((u_char*)dump, &h, frame);
	/* second frame: truncated to 14 + 25 bytes (IP header + 5) */
	h.caplen = h.len = 14 + 25;
	pcap_dump((u_char*)dump, &h, frame);
	/* third frame: IHL = 0 */
	frame[14] = 0x40;
	h.caplen = h.len = 14 + 40;
	pcap_dump((u_char*)dump, &h, frame);
	pcap_dump_close(dump);
	pcap_close(dead);

	ctx.pcapfp = pcap_open_offline(path, err);
	CHECK(ctx.pcapfp != NULL);
	if (!ctx.pcapfp) return;
	ctx.linkhdr_size = 14;
	ctx.local.sin_addr.s_addr = htonl(DADDR);
	ctx.remote.sin_addr.s_addr = htonl(SADDR);
	cfg.dst_port = 80;
	cfg.opt_quiet = TRUE;
	cfg.count = -1;
	hping_stats_init(&stats);
	delaytable_add(5, 4321, S_SENT);
	wait_packet();
	CHECK_EQ_INT(stats.received, 1);
	CHECK_EQ_INT(ctx.tcp_exitcode, 0x12);
	wait_packet();			/* truncated: ignored */
	CHECK_EQ_INT(stats.received, 1);
	wait_packet();			/* IHL 0: ignored */
	CHECK_EQ_INT(stats.received, 1);
	pcap_close(ctx.pcapfp);
	ctx.pcapfp = NULL;
	unlink(path);
}

/* The link-layer header the capture of 'dlt' carries in front of the IP
 * datagram, written into 'hdr'. Returns its length. */
static int lldr_header(int dlt, unsigned char *hdr)
{
	memset(hdr, 0, 24);
	switch (dlt) {
	case DLT_EN10MB:
		hdr[5] = 1; hdr[11] = 2;	/* dst/src MAC */
		hdr[12] = 0x08; hdr[13] = 0x00;
		return 14;
	case DLT_RAW:
		return 0;
	case DLT_NULL:			/* host-order AF_INET */
		hdr[0] = 2;
		return 4;
#ifdef DLT_LOOP
	case DLT_LOOP:			/* network-order AF_INET */
		hdr[3] = 2;
		return 4;
#endif
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
		hdr[1] = 0;		/* packet type: to us */
		hdr[3] = 1;		/* ARPHRD_ETHER */
		hdr[5] = 6;		/* address length */
		hdr[14] = 0x08; hdr[15] = 0x00;
		return 16;
#endif
#ifdef DLT_LINUX_SLL2
	case DLT_LINUX_SLL2:
		hdr[0] = 0x08; hdr[1] = 0x00;	/* protocol */
		hdr[7] = 2;		/* interface index */
		hdr[9] = 1;		/* ARPHRD_ETHER */
		hdr[11] = 6;		/* address length */
		return 20;
#endif
	}
	return -1;
}

/* wait_packet() must find the IP header behind the link header of every
 * supported capture type, with the offset taken from the capture's own
 * DLT (get_linkhdr_size) rather than assumed to be Ethernet. */
static void test_link_layer_types(void)
{
	static const int dlts[] = {
		DLT_EN10MB, DLT_RAW, DLT_NULL,
#ifdef DLT_LOOP
		DLT_LOOP,
#endif
#ifdef DLT_LINUX_SLL
		DLT_LINUX_SLL,
#endif
#ifdef DLT_LINUX_SLL2
		DLT_LINUX_SLL2,
#endif
	};
	unsigned char frame[24 + 60], hdr[24];
	unsigned short ck;
	char path[128], err[PCAP_ERRBUF_SIZE];
	unsigned int i;
	int hlen, lhs;

	TEST("dltype_to_lhs: the supported types and their header sizes");
	CHECK_EQ_INT(dltype_to_lhs(DLT_EN10MB), 14);
	CHECK_EQ_INT(dltype_to_lhs(DLT_RAW), 0);
	CHECK_EQ_INT(dltype_to_lhs(DLT_NULL), 4);
#ifdef DLT_LOOP
	CHECK_EQ_INT(dltype_to_lhs(DLT_LOOP), 4);
#endif
#ifdef DLT_LINUX_SLL
	CHECK_EQ_INT(dltype_to_lhs(DLT_LINUX_SLL), 16);
#endif
#ifdef DLT_LINUX_SLL2
	CHECK_EQ_INT(dltype_to_lhs(DLT_LINUX_SLL2), 20);
#endif
#ifdef DLT_LANE8023			/* LANE header + Ethernet header */
	CHECK_EQ_INT(dltype_to_lhs(DLT_LANE8023), 16);
#endif
	CHECK_EQ_INT(dltype_to_lhs(DLT_ATM_RFC1483), 8);
	CHECK_EQ_INT(dltype_to_lhs(DLT_PPP), 4);
	CHECK_EQ_INT(dltype_to_lhs(DLT_SLIP), 16);
	CHECK_EQ_INT(dltype_to_lhs(DLT_FDDI), 13);

	TEST("dltype_to_lhs: a variable-length or unknown type is refused");
	/* 802.11 and radiotap headers are not fixed size: guessing one
	 * would misparse every frame, so they are not supported. */
#ifdef DLT_IEEE802_11
	CHECK_EQ_INT(dltype_to_lhs(DLT_IEEE802_11), -1);
#endif
#ifdef DLT_IEEE802			/* token ring: variable routing field */
	CHECK_EQ_INT(dltype_to_lhs(DLT_IEEE802), -1);
#endif
#ifdef DLT_IEEE802_11_RADIO
	CHECK_EQ_INT(dltype_to_lhs(DLT_IEEE802_11_RADIO), -1);
#endif
	CHECK_EQ_INT(dltype_to_lhs(31337), -1);
	CHECK_EQ_INT(dltype_to_lhs(-1), -1);

	for (i = 0; i < sizeof(dlts)/sizeof(dlts[0]); i++) {
		pcap_t *dead;
		pcap_dumper_t *dump;
		struct pcap_pkthdr h;
		unsigned long received;

		TEST(pcap_datalink_val_to_name(dlts[i]));
		lhs = lldr_header(dlts[i], hdr);
		CHECK_EQ_INT(lhs, dltype_to_lhs(dlts[i]));
		if (lhs < 0)
			continue;

		memset(frame, 0, sizeof(frame));
		memcpy(frame, hdr, (size_t) lhs);
		hlen = tu_build_ip(frame + lhs, 0, 40, 6, SADDR, DADDR);
		tu_build_tcp(frame + lhs + hlen, 80, 4321, 0x12, 5);
		ck = tu_l4_cksum(SADDR, DADDR, 6, frame + lhs + hlen, 20);
		memcpy(frame + lhs + hlen + 16, &ck, 2);

		snprintf(path, sizeof(path), "/tmp/hping-test-dlt%d-%ld.pcap",
			dlts[i], (long) getpid());
		dead = pcap_open_dead(dlts[i], 65535);
		CHECK(dead != NULL);
		if (!dead) continue;
		dump = pcap_dump_open(dead, path);
		CHECK(dump != NULL);
		if (!dump) { pcap_close(dead); continue; }
		memset(&h, 0, sizeof(h));
		h.caplen = h.len = (bpf_u_int32) (lhs + 40);
		pcap_dump((u_char*)dump, &h, frame);
		/* a frame shorter than the link header must be dropped,
		 * not read past its end */
		if (lhs > 0) {
			h.caplen = h.len = (bpf_u_int32) (lhs - 1);
			pcap_dump((u_char*)dump, &h, frame);
		}
		pcap_dump_close(dump);
		pcap_close(dead);

		ctx.pcapfp = pcap_open_offline(path, err);
		CHECK(ctx.pcapfp != NULL);
		if (!ctx.pcapfp) { unlink(path); continue; }
		/* the offset comes from the capture, not from a constant */
		ctx.linkhdr_size = 0;
		CHECK_EQ_INT(get_linkhdr_size(NULL), 0);
		CHECK_EQ_INT((int) ctx.linkhdr_size, lhs);

		ctx.local.sin_addr.s_addr = htonl(DADDR);
		ctx.remote.sin_addr.s_addr = htonl(SADDR);
		cfg.dst_port = 80;
		cfg.opt_quiet = TRUE;
		cfg.count = -1;
		hping_stats_init(&stats);
		delaytable_add(5, 4321, S_SENT);
		received = (unsigned long) stats.received;
		wait_packet();
		CHECK_EQ_INT((int) (stats.received - received), 1);
		if (lhs > 0) {
			wait_packet();	/* shorter than the link header */
			CHECK_EQ_INT((int) (stats.received - received), 1);
		}
		pcap_close(ctx.pcapfp);
		ctx.pcapfp = NULL;
		unlink(path);
	}

	TEST("get_linkhdr_size: an unsupported type fails without setting a size");
	{
		pcap_t *dead;
		pcap_dumper_t *dump;
		int unsupported = 31337;

#ifdef DLT_IEEE802_11_RADIO
		unsupported = DLT_IEEE802_11_RADIO;
#endif
		snprintf(path, sizeof(path), "/tmp/hping-test-dltbad-%ld.pcap",
			(long) getpid());
		dead = pcap_open_dead(unsupported, 65535);
		CHECK(dead != NULL);
		if (dead) {
			dump = pcap_dump_open(dead, path);
			CHECK(dump != NULL);
			if (dump) pcap_dump_close(dump);
			pcap_close(dead);
		}
		ctx.pcapfp = pcap_open_offline(path, err);
		CHECK(ctx.pcapfp != NULL);
		if (ctx.pcapfp) {
			ctx.linkhdr_size = 14;
			CHECK_EQ_INT(get_linkhdr_size(NULL), -1);
			/* the old code stored (unsigned) -1 here, which is
			 * a 4 GiB VLA at the next wait_packet() */
			CHECK_EQ_INT((int) ctx.linkhdr_size, 14);
			pcap_close(ctx.pcapfp);
			ctx.pcapfp = NULL;
		}
		unlink(path);
	}
}

int main(void)
{
	hping_config_init(&cfg);
	hping_context_init(&ctx);
	hping_stats_init(&stats);
	test_icmp_unreach_rtt();
	test_print_tcp_timestamp();
	test_handle_hcmp();
	test_wait_packet_savefile();
	test_link_layer_types();
	return tu_report("test_waitpacket");
}
