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

int main(void)
{
	hping_config_init(&cfg);
	hping_context_init(&ctx);
	hping_stats_init(&stats);
	test_icmp_unreach_rtt();
	test_print_tcp_timestamp();
	test_handle_hcmp();
	test_wait_packet_savefile();
	return tu_report("test_waitpacket");
}
