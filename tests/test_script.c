/* test_script.c -- regression tests for the Tcl binding (script.c).
 *
 * Built only when Tcl support is enabled. script.c is #included to reach
 * its static functions. Packets come from a pcap savefile, the Tcl
 * commands are exercised in an interpreter created here: no interface is
 * opened, no packet is sent, and the user's ~/.hpingrc is never read
 * (HOME points to an empty temporary directory). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "script.c"
#include "globals.h"
#include "testutil.h"

#define SADDR 0xc0a80106UL
#define DADDR 0xc0a80107UL

static const char *make_savefile(int npkts)
{
	static char path[128];
	unsigned char f[14 + 60];
	unsigned short ck;
	pcap_t *dead;
	pcap_dumper_t *dump;
	struct pcap_pkthdr h;
	int i, hlen;

	snprintf(path, sizeof(path), "/tmp/hping-test-script-%ld.pcap", (long)getpid());
	dead = pcap_open_dead(DLT_EN10MB, 65535);
	dump = pcap_dump_open(dead, path);
	if (!dump) {
		fprintf(stderr, "pcap_dump_open: %s\n", pcap_geterr(dead));
		exit(2);
	}
	memset(&h, 0, sizeof(h));
	for (i = 0; i < npkts; i++) {
		memset(f, 0, sizeof(f));
		f[12] = 0x08; f[13] = 0x00;
		hlen = tu_build_ip(f + 14, 0, 40, 6, SADDR + i, DADDR);
		tu_build_tcp(f + 14 + hlen, 1000 + i, 80, 0x02, 5);
		ck = tu_l4_cksum(SADDR + i, DADDR, 6, f + 14 + hlen, 20);
		memcpy(f + 14 + hlen + 16, &ck, 2);
		h.ts.tv_sec = i;
		h.caplen = h.len = 14 + 40;
		pcap_dump((u_char*)dump, &h, f);
	}
	pcap_dump_close(dump);
	pcap_close(dead);
	return path;
}

static void test_recv_packets(Tcl_Interp *interp)
{
	struct recv_handler ra;
	char err[PCAP_ERRBUF_SIZE];
	const char *path = make_savefile(3);
	Tcl_Obj *list, *el;
	Tcl_Size n, blen;
	int i, r;
	unsigned char *bytes;
	char expect[64];

	TEST("hping recv: every packet of a multi-packet read is described from its own start");
	/* Regression: the buffer pointer was advanced by the link header
	 * size for every packet but the next read still used the full
	 * buffer size at the advanced position; the second packet was
	 * therefore described from 2*lhs bytes into the frame (garbage),
	 * and the read itself could write past the buffer. */
	memset(&ra, 0, sizeof(ra));
	ra.rh_pcapfp = pcap_open_offline(path, err);
	CHECK(ra.rh_pcapfp != NULL);
	if (!ra.rh_pcapfp) return;
	strcpy(ra.rh_ifname, "savefile");
	ra.rh_linkhdrsize = dltype_to_lhs(pcap_datalink(ra.rh_pcapfp));
	CHECK_EQ_INT(ra.rh_linkhdrsize, 14);

	list = Tcl_NewListObj(0, NULL);
	Tcl_IncrRefCount(list);
	r = HpingRecvPackets(&ra, interp, list, 0, 3, 1, 0);
	CHECK_EQ_INT(r, 0);
	CHECK_EQ_INT(Tcl_ListObjLength(interp, list, &n), TCL_OK);
	CHECK_EQ_INT(n, 3);
	for (i = 0; i < 3 && i < n; i++) {
		const char *apd;
		Tcl_ListObjIndex(interp, list, i, &el);
		apd = Tcl_GetString(el);
		snprintf(expect, sizeof(expect), "saddr=192.168.1.%d,", 6 + i);
		CHECK(strstr(apd, expect) != NULL);
		snprintf(expect, sizeof(expect), "+tcp(sport=%d,dport=80,", 1000 + i);
		CHECK(strstr(apd, expect) != NULL);
		CHECK(strncmp(apd, "ip(", 3) == 0);
	}
	Tcl_DecrRefCount(list);

	TEST("hping recv: end of savefile is reported as an error, not a hang");
	list = Tcl_NewListObj(0, NULL);
	Tcl_IncrRefCount(list);
	r = HpingRecvPackets(&ra, interp, list, -1, 1, 1, 0);
	CHECK_EQ_INT(r, 1);
	CHECK(strstr(Tcl_GetStringResult(interp), "Error reading packets") != NULL);
	Tcl_DecrRefCount(list);
	pcap_close(ra.rh_pcapfp);

	TEST("hping recvraw: packets are returned as exact byte arrays");
	ra.rh_pcapfp = pcap_open_offline(path, err);
	CHECK(ra.rh_pcapfp != NULL);
	if (!ra.rh_pcapfp) return;
	list = Tcl_NewListObj(0, NULL);
	Tcl_IncrRefCount(list);
	r = HpingRecvPackets(&ra, interp, list, 0, 2, 0, 0);
	CHECK_EQ_INT(r, 0);
	CHECK_EQ_INT(Tcl_ListObjLength(interp, list, &n), TCL_OK);
	CHECK_EQ_INT(n, 2);
	if (n == 2) {
		Tcl_ListObjIndex(interp, list, 1, &el);
		bytes = Tcl_GetByteArrayFromObj(el, &blen);
		CHECK_EQ_INT(blen, 40);
		CHECK_EQ_INT(bytes[0], 0x45);
		CHECK_EQ_INT(bytes[15], 7);		/* 192.168.1.7 */
		CHECK_EQ_INT(bytes[12+3], 7);		/* saddr 192.168.1.7 (2nd pkt) */
		CHECK_EQ_INT((bytes[20] << 8) | bytes[21], 1001);
	}
	Tcl_DecrRefCount(list);
	pcap_close(ra.rh_pcapfp);
	unlink(path);

	TEST("GetPacketDescription: errors are reported, not ignored");
	CHECK(GetPacketDescription(interp, (unsigned char*)"x", -1, 0) == NULL);
	{
		unsigned char raw[40];
		char *d;
		memset(raw, 0, sizeof(raw));
		tu_build_ip(raw, 0, 40, 6, SADDR, DADDR);
		tu_build_tcp(raw + 20, 1, 2, 0, 5);
		d = GetPacketDescription(interp, raw, 40, 0);
		CHECK(d != NULL);
		if (d) {
			CHECK(strstr(d, "ip(ihl=0x5,ver=0x4") == d);
			free(d);
		}
		/* a bogus tot_len used to wrap the remaining size */
		raw[2] = 0; raw[3] = 5;
		d = GetPacketDescription(interp, raw, 40, 1);
		CHECK(d != NULL);
		free(d);
	}
}

static int eval(Tcl_Interp *interp, const char *script, const char **result)
{
	int r = Tcl_Eval(interp, script);
	*result = Tcl_GetStringResult(interp);
	return r;
}

static void test_commands(Tcl_Interp *interp)
{
	const char *res;
	static const char pkt[] = "{ip(saddr=1.2.3.4,daddr=5.6.7.8,ttl=64)+tcp(sport=1,dport=80,flags=s)+ip(saddr=9.9.9.9,daddr=8.8.8.8)}";
	char cmd[512];

	TEST("hping getfield/hasfield/setfield/delfield");
	snprintf(cmd, sizeof(cmd), "hping getfield ip saddr %s", pkt);
	CHECK_EQ_INT(eval(interp, cmd, &res), TCL_OK);
	CHECK_EQ_STR(res, "1.2.3.4");
	snprintf(cmd, sizeof(cmd), "hping getfield ip saddr 1 %s", pkt);
	CHECK_EQ_INT(eval(interp, cmd, &res), TCL_OK);
	CHECK_EQ_STR(res, "9.9.9.9");
	snprintf(cmd, sizeof(cmd), "hping getfield tcp dport %s", pkt);
	CHECK_EQ_INT(eval(interp, cmd, &res), TCL_OK);
	CHECK_EQ_STR(res, "80");
	snprintf(cmd, sizeof(cmd), "hping hasfield tcp win %s", pkt);
	CHECK_EQ_INT(eval(interp, cmd, &res), TCL_OK);
	CHECK_EQ_STR(res, "0");
	snprintf(cmd, sizeof(cmd), "hping setfield ip ttl 5 %s", pkt);
	CHECK_EQ_INT(eval(interp, cmd, &res), TCL_OK);
	CHECK(strstr(res, "ttl=5)+tcp(") != NULL);
	snprintf(cmd, sizeof(cmd), "hping delfield ip ttl %s", pkt);
	CHECK_EQ_INT(eval(interp, cmd, &res), TCL_OK);
	CHECK(strstr(res, "daddr=5.6.7.8)+tcp(") != NULL);
	/* Regression: a non-numeric skip was silently taken as 0 */
	snprintf(cmd, sizeof(cmd), "hping getfield ip saddr x %s", pkt);
	CHECK_EQ_INT(eval(interp, cmd, &res), TCL_ERROR);
	snprintf(cmd, sizeof(cmd), "hping hasfield ip saddr x %s", pkt);
	CHECK_EQ_INT(eval(interp, cmd, &res), TCL_ERROR);
	snprintf(cmd, sizeof(cmd), "hping delfield ip saddr x %s", pkt);
	CHECK_EQ_INT(eval(interp, cmd, &res), TCL_ERROR);
	snprintf(cmd, sizeof(cmd), "hping setfield ip saddr 1.1.1.1 x %s", pkt);
	CHECK_EQ_INT(eval(interp, cmd, &res), TCL_ERROR);

	TEST("hping recv/recvraw argument validation happens before opening anything");
	CHECK_EQ_INT(eval(interp, "hping recv", &res), TCL_ERROR);
	CHECK_EQ_INT(eval(interp, "hping recv lo abc", &res), TCL_ERROR);
	CHECK(strstr(res, "expected integer") != NULL);
	CHECK_EQ_INT(eval(interp, "hping recvraw lo 10 abc", &res), TCL_ERROR);
	CHECK_EQ_INT(eval(interp, "hping recv lo 10 -5", &res), TCL_ERROR);
	CHECK(strstr(res, "maxpackets") != NULL);

	TEST("hping checksum");
	CHECK_EQ_INT(eval(interp, "hping checksum abcd", &res), TCL_OK);
	{
		/* 'hping checksum' returns ars_cksum()'s value, i.e. the
		 * checksum word as laid out in memory (historical behaviour,
		 * platform byte order) -- exactly what tu_cksum() returns */
		unsigned short want = tu_cksum((const unsigned char*)"abcd", 4);
		char buf[16];
		snprintf(buf, sizeof(buf), "%u", want);
		CHECK_EQ_STR(res, buf);
	}

	TEST("hping sendraw rejects short packets before touching the socket");
	CHECK_EQ_INT(eval(interp, "hping sendraw abc", &res), TCL_ERROR);
	CHECK(strstr(res, "shorter than IPv4 header") != NULL);

	TEST("bignum commands");
	CHECK_EQ_INT(eval(interp, "+ 1 2 3", &res), TCL_OK);
	CHECK_EQ_STR(res, "6");
	CHECK_EQ_INT(eval(interp, "- 10 3", &res), TCL_OK);
	CHECK_EQ_STR(res, "7");
	CHECK_EQ_INT(eval(interp, "- 5", &res), TCL_OK);
	CHECK_EQ_STR(res, "-5");
	CHECK_EQ_INT(eval(interp, "** 2 100", &res), TCL_OK);
	CHECK_EQ_STR(res, "1267650600228229401496703205376");
	CHECK_EQ_INT(eval(interp, "% [** 2 100] 7", &res), TCL_OK);
	CHECK_EQ_STR(res, "2");
	CHECK_EQ_INT(eval(interp, "> 5 3", &res), TCL_OK);
	CHECK_EQ_STR(res, "1");
	CHECK_EQ_INT(eval(interp, "== 5 5", &res), TCL_OK);
	CHECK_EQ_STR(res, "1");
	CHECK_EQ_INT(eval(interp, "+ 1 notanumber", &res), TCL_ERROR);
	CHECK_EQ_INT(eval(interp, "** 2 -1", &res), TCL_ERROR);
	/* the mpz object is duplicated and converted back and forth */
	CHECK_EQ_INT(eval(interp, "set a [+ 1 1]; set b $a; lappend b x; expr {$a + 1}", &res), TCL_OK);
	CHECK_EQ_STR(res, "3");

	TEST("hping: unknown subcommand");
	CHECK_EQ_INT(eval(interp, "hping bogus", &res), TCL_ERROR);
	CHECK(strstr(res, "Bad option") != NULL);
	CHECK_EQ_INT(eval(interp, "set hping_version", &res), TCL_OK);
	CHECK_EQ_STR(res, RELEASE_VERSION);

	TEST("the styxwire command name is registered alongside hping");
	CHECK_EQ_INT(eval(interp, "set styxwire_version", &res), TCL_OK);
	CHECK_EQ_STR(res, STYXWIRE_VERSION);
	CHECK_EQ_INT(eval(interp, "styxwire checksum abcd", &res), TCL_OK);
}

static void test_offline(Tcl_Interp *interp)
{
	const char *res;

	TEST("hping build/describe: APD -> binary -> APD round trip, no socket");
	CHECK_EQ_INT(eval(interp,
		"hping describe [hping build "
		"{ip(saddr=1.2.3.4,daddr=5.6.7.8,ttl=7)+tcp(sport=1,dport=80,flags=s)}]",
		&res), TCL_OK);
	CHECK(strstr(res, "ip(") == res);
	CHECK(strstr(res, "saddr=1.2.3.4") != NULL);
	CHECK(strstr(res, "ttl=7") != NULL);
	CHECK(strstr(res, "+tcp(sport=1,dport=80,") != NULL);
	CHECK(strstr(res, "flags=s") != NULL);

	TEST("hping build: -nocompile keeps the given (bogus) checksum/len");
	CHECK_EQ_INT(eval(interp,
		"binary scan [hping build -nocompile "
		"{ip(saddr=1.2.3.4,daddr=5.6.7.8,cksum=0x1111,totlen=99)+udp(sport=1,dport=2,cksum=0)}] "
		"H4 tl", &res), TCL_OK); /* first 2 bytes: version/ihl + tos */

	TEST("hping build: byte length matches the packet");
	CHECK_EQ_INT(eval(interp,
		"string length [hping build {ip(daddr=1.2.3.4)+icmp(type=8)+data(str=hello)}]",
		&res), TCL_OK);
	CHECK_EQ_STR(res, "33"); /* 20 IP + 8 ICMP + 5 data */

	TEST("hping build: an invalid description is a Tcl error");
	CHECK_EQ_INT(eval(interp, "hping build {ip()+nosuchlayer()}", &res), TCL_ERROR);
	CHECK(strstr(res, "building error") != NULL);
	CHECK_EQ_INT(eval(interp, "hping build {tcp(dport=80)}", &res), TCL_ERROR);
	CHECK(strstr(res, "compilation error") != NULL); /* TCP checksum needs IP */

	TEST("hping describe: -hex data and short packets");
	CHECK_EQ_INT(eval(interp,
		"hping describe -hex [hping build {ip(daddr=1.2.3.4)+data(hex=00ff10)}]", &res), TCL_OK);
	CHECK(strstr(res, "data(hex=00ff10)") != NULL);
	CHECK_EQ_INT(eval(interp, "hping describe [binary format H* 4500]", &res), TCL_OK);

	TEST("hping validate: good and bad descriptions");
	CHECK_EQ_INT(eval(interp, "hping validate {ip(daddr=1.2.3.4)+tcp(dport=80)}", &res), TCL_OK);
	CHECK_EQ_STR(res, "1");
	CHECK_EQ_INT(eval(interp, "hping validate {ip()+bogus()}", &res), TCL_OK);
	CHECK(strstr(res, "Unknown keyword") != NULL);

	TEST("hping build result feeds hping describe as a byte array (binary safe)");
	CHECK_EQ_INT(eval(interp,
		"hping describe [hping build {ip(daddr=1.2.3.4)+data(hex=00010280ff)}]", &res), TCL_OK);
	CHECK(strstr(res, "data(") != NULL);
}

int main(void)
{
	Tcl_Interp *interp;
	char home[128];

	hping_config_init(&cfg);
	hping_context_init(&ctx);
	hping_stats_init(&stats);

	/* Keep the user's ~/.hpingrc out of the test run */
	snprintf(home, sizeof(home), "/tmp/hping-test-home-%ld", (long)getpid());
	mkdir(home, 0700);
	setenv("HOME", home, 1);

	Tcl_FindExecutable("test_script");
	interp = Tcl_CreateInterp();
	if (HpingTcl_AppInit(interp) != TCL_OK) {
		fprintf(stderr, "test_script: Tcl init failed: %s\n",
			Tcl_GetStringResult(interp));
		fprintf(stderr, "test_script: SKIPPED (Tcl runtime library not usable)\n");
		rmdir(home);
		return 77;
	}
	test_recv_packets(interp);
	test_commands(interp);
	test_offline(interp);
	Tcl_DeleteInterp(interp);
	rmdir(home);
	return tu_report("test_script");
}
