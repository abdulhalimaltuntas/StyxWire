/* test_scan.c -- the scan mode (scan.c): port list parsing, reply
 * handling, and the whole probing state machine driven offline with the
 * fake clock (no fork, no shared memory, no socket).
 *
 * scan.c is #included to reach its static functions. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "scan.c"
#include "testutil.h"
#include "stub_send.h"
#include "fakeio.h"

#define SADDR 0xc0a80106UL /* remote */
#define DADDR 0xc0a80107UL /* local  */

static struct portinfo *new_table(void)
{
	struct portinfo *pi = calloc(MAXPORT + 2, sizeof(*pi));
	int i;
	for (i = 0; i <= MAXPORT; i++)
		pi[i].retry = opt_scan_probes;
	return pi;
}

static int count_active(struct portinfo *pi)
{
	int i, n = 0;
	for (i = 0; i <= MAXPORT; i++)
		n += pi[i].active != 0;
	return n;
}

static void test_parse_ports(void)
{
	struct portinfo *pi = new_table();
	char spec[64];

	TEST("parse_ports: list, range, negation");
	strcpy(spec, "22,80-82,!81");
	CHECK_EQ_INT(parse_ports(pi, spec), 0);
	CHECK_EQ_INT(count_active(pi), 3);
	CHECK(pi[22].active && pi[80].active && pi[82].active && !pi[81].active);

	TEST("parse_ports: reversed range");
	memset(pi, 0, sizeof(*pi) * (MAXPORT + 2));
	strcpy(spec, "10-5");
	CHECK_EQ_INT(parse_ports(pi, spec), 0);
	CHECK_EQ_INT(count_active(pi), 6);

	TEST("parse_ports: range beyond 65535 is an error (was an OOB write)");
	/* Regression: "1-70000" wrote past the 65537 entries of the table. */
	memset(pi, 0, sizeof(*pi) * (MAXPORT + 2));
	strcpy(spec, "1-70000");
	CHECK_EQ_INT(parse_ports(pi, spec), 1);
	strcpy(spec, "70000");
	CHECK_EQ_INT(parse_ports(pi, spec), 1);

	TEST("parse_ports: dangling '-' (uninitialised token pointer)");
	strcpy(spec, "1-");
	CHECK_EQ_INT(parse_ports(pi, spec), 1);
	strcpy(spec, "-");
	CHECK_EQ_INT(parse_ports(pi, spec), 1);
	strcpy(spec, "a-b");
	CHECK_EQ_INT(parse_ports(pi, spec), 1);

	TEST("parse_ports: 'all'");
	memset(pi, 0, sizeof(*pi) * (MAXPORT + 2));
	strcpy(spec, "all,!0");
	CHECK_EQ_INT(parse_ports(pi, spec), 0);
	CHECK_EQ_INT(count_active(pi), MAXPORT);
	free(pi);
}

static void test_tcp_strflags(void)
{
	char s[9];

	TEST("tcp_strflags");
	CHECK_EQ_STR(tcp_strflags(s, 0x12), ".S..A...");
	CHECK_EQ_STR(tcp_strflags(s, 0x20), ".....U..");	/* URG was printed as Y */
	CHECK_EQ_STR(tcp_strflags(s, 0xff), "FSRPAUXY");
}

static void test_process_packet(void)
{
	struct portinfo *pi = new_table();
	unsigned char f[128];
	int hlen;

	ctx.linkhdr_size = 14;
	ctx.local.sin_addr.s_addr = htonl(DADDR);
	ctx.remote.sin_addr.s_addr = htonl(SADDR);
	cfg.initsport = 4321;
	cfg.opt_verbose = FALSE;
	pi[80].active = 1;
	pi[81].active = 1;

	TEST("scan: ICMP reply quoting the probe (8 byte ICMP header copy)");
	/* Regression: memcpy(&icmp, p, sizeof(subtcp)) wrote 20 bytes into
	 * the 8 byte ICMP header on the stack. */
	memset(f, 0, sizeof(f));
	hlen = tu_build_ip(f + 14, 0, 56, 1, 0x0a000001UL, DADDR); /* from a router */
	f[14+20] = 3; f[14+21] = 3;				/* port unreachable */
	tu_build_ip(f + 14 + 28, 0, 40, 6, DADDR, SADDR);	/* quoted probe */
	tu_build_tcp(f + 14 + 48, 4321, 81, 0x02, 5);
	CHECK_EQ_INT(scan_process_packet(pi, (char*)f, 14 + 56 + 12), 1);
	CHECK_EQ_INT(pi[81].active, 0);
	CHECK_EQ_INT(pi[80].active, 1);

	TEST("scan: ICMP too short to quote the probe is ignored");
	pi[81].active = 1;
	CHECK_EQ_INT(scan_process_packet(pi, (char*)f, 14 + 56 - 1), 0);
	CHECK_EQ_INT(pi[81].active, 1);

	TEST("scan: TCP SYN+ACK reply");
	memset(f, 0, sizeof(f));
	hlen = tu_build_ip(f + 14, 0, 40, 6, SADDR, DADDR);
	tu_build_tcp(f + 14 + hlen, 80, 4321, 0x12, 5);
	CHECK_EQ_INT(scan_process_packet(pi, (char*)f, 14 + 40), 1);
	CHECK_EQ_INT(pi[80].active, 0);

	TEST("scan: truncated TCP header is ignored");
	pi[80].active = 1;
	CHECK_EQ_INT(scan_process_packet(pi, (char*)f, 14 + 39), 0);
	CHECK_EQ_INT(pi[80].active, 1);

	TEST("scan: IHL larger than the datagram (negative length) is ignored");
	/* Regression: (iplen - iphdrlen) < sizeof(tcp) compared a negative
	 * int with size_t, which is false, so the TCP header was read
	 * from beyond the captured data. */
	f[14] = 0x4f;
	CHECK_EQ_INT(scan_process_packet(pi, (char*)f, 14 + 40), 0);
	f[14] = 0x41;
	CHECK_EQ_INT(scan_process_packet(pi, (char*)f, 14 + 40), 0);
	CHECK_EQ_INT(scan_process_packet(pi, (char*)f, 5), 0);
	CHECK_EQ_INT(scan_process_packet(pi, (char*)f, -1), 0);
	CHECK_EQ_INT(pi[80].active, 1);
	free(pi);
}

/* run scan_run() with stdout/stderr captured into 'out' */
static int run_scan_captured(char *out, size_t outlen)
{
	FILE *tmp = tmpfile();
	int saved_out = dup(1), saved_err = dup(2), rc;
	size_t n;

	fflush(stdout); fflush(stderr);
	dup2(fileno(tmp), 1); dup2(fileno(tmp), 2);
	rc = scan_run();
	fflush(stdout); fflush(stderr);
	dup2(saved_out, 1); dup2(saved_err, 2);
	close(saved_out); close(saved_err);
	rewind(tmp);
	n = fread(out, 1, outlen - 1, tmp);
	out[n] = '\0';
	fclose(tmp);
	return rc;
}

static void scan_session_reset(const char *ports)
{
	hping_config_init(&cfg);
	hping_context_init(&ctx);
	hping_stats_init(&stats);
	stub_send_reset();
	fakeio_install(1000000);
	avrgms = 0;
	avrgcount = 0;

	strcpy(cfg.targetname, "192.168.1.6");
	strcpy(ctx.targetstraddr, "192.168.1.6");
	ctx.local.sin_addr.s_addr = htonl(FAKE_LOCAL);
	ctx.remote.sin_addr.s_addr = htonl(FAKE_REMOTE);
	ctx.linkhdr_size = 0;
	cfg.initsport = 4321;
	ctx.src_port = 4321;
	cfg.tcp_th_flags = TH_SYN;
	cfg.opt_scanmode = TRUE;
	cfg.opt_scanports = strdup(ports);
	/* what parse_options() does for scan mode without -i */
	cfg.opt_waitinusec = TRUE;
	cfg.usec_delay.it_value.tv_usec = cfg.usec_delay.it_interval.tv_usec = 0;
}

static void test_scan_state_machine(void)
{
	char out[4096];
	int rc, i, probes80 = 0, probes82 = 0;

	TEST("scan: answered ports stop being probed, silent ones get every retry");
	scan_session_reset("80-82");
	/* 80 answers the first probe, 81 the second one, 82 never */
	script_reply_from(1000000 + 100, 80, 4321, 0x12);
	script_reply_from(1000000 + 900000, 81, 4321, 0x14); /* RST: closed */
	rc = run_scan_captured(out, sizeof(out));
	CHECK_EQ_INT(rc, 0);
	CHECK_EQ_INT(ctx.stop_reason, HPING_STOP_COUNT);
	CHECK(strstr(out, "3 ports to scan") != NULL);
	CHECK(strstr(out, "   80 ") != NULL);		/* SYN+ACK line printed */
	CHECK(strstr(out, ".S..A...") != NULL);
	CHECK(strstr(out, "All replies received. Done.") != NULL);
	CHECK(strstr(out, "Not responding ports: (82 ") != NULL);
	CHECK(strstr(out, "(80 ") == NULL);
	CHECK(strstr(out, "(81 ") == NULL);
	/* At full speed the first rounds go out before any reply can be
	 * read (exactly like the historical two-process scanner): the
	 * answered ports are re-probed until their reply is seen at the
	 * first pause (round 3), the silent one gets every retry. */
	probes80 = stub_probes_to(80);
	probes82 = stub_probes_to(82);
	CHECK(probes80 >= 1 && probes80 <= 3);
	CHECK(stub_probes_to(81) >= 1 && stub_probes_to(81) <= 3);
	CHECK_EQ_INT(probes82, opt_scan_probes);
	CHECK_EQ_INT((int) stub_send_calls, probes80 + stub_probes_to(81) + probes82);
	for (i = 0; i < (int) stub_send_calls; i++)
		CHECK(stub_send_dport[i] >= 80 && stub_send_dport[i] <= 82);
	/* the loop kept the source port fixed for every probe */
	CHECK_EQ_INT((stub_last_packet[0] << 8) | stub_last_packet[1], 4321);
	CHECK_EQ_INT((stub_last_packet[2] << 8) | stub_last_packet[3], 82);
	/* the last two rounds slowed down: interval 0 -> 1 -> 11 -> 111 (us) */
	CHECK(hping_monotonic_us() > 1000000);
	hping_destroy();

	TEST("scan: nothing answers -> one extra second for late replies, then done");
	scan_session_reset("1000");
	rc = run_scan_captured(out, sizeof(out));
	CHECK_EQ_INT(rc, 0);
	CHECK_EQ_INT(stub_send_calls, opt_scan_probes);
	CHECK(strstr(out, "Not responding ports: (1000 ") != NULL);
	/* rounds >= 3 wait a second each (no RTT known) and the end waits
	 * one more: 6 pauses of a second at least */
	CHECK(hping_monotonic_us() >= 1000000 + 7 * 1000000LL);
	hping_destroy();

	TEST("scan: bad port list is rejected without running");
	scan_session_reset("1-");
	rc = run_scan_captured(out, sizeof(out));
	CHECK_EQ_INT(rc, 1);
	CHECK(strstr(out, "Ports syntax error") != NULL);
	CHECK_EQ_INT(stub_send_calls, 0);
	hping_destroy();

	TEST("scan: a stop request (SIGINT) ends the scan and frees the table");
	scan_session_reset("1-20");
	stop_after_waits = 3;
	rc = run_scan_captured(out, sizeof(out));
	CHECK_EQ_INT(rc, 0);
	CHECK_EQ_INT(ctx.stop_reason, HPING_STOP_SIGNAL);
	CHECK(stub_send_calls >= 1);
	hping_destroy();

	TEST("scan: a send error stops the scan with status 1");
	scan_session_reset("22");
	stub_send_fail = 1;
	rc = run_scan_captured(out, sizeof(out));
	CHECK_EQ_INT(rc, 1);
	CHECK_EQ_INT(ctx.stop_reason, HPING_STOP_ERROR);
	hping_destroy();
}

int main(void)
{
	hping_config_init(&cfg);
	hping_context_init(&ctx);
	hping_stats_init(&stats);
	test_parse_ports();
	test_tcp_strflags();
	test_process_packet();
	test_scan_state_machine();
	return tu_report("test_scan");
}
