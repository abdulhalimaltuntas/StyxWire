/* test_core.c -- offline regression tests for the hping3 core helpers,
 * the ARS packet splitter/serializer (split.c, rapd.c, apd.c, ars.c),
 * display_ipopt(), send_icmp_other() and pcap_recv().
 *
 * Each test documents the defect it guards against ("Regression:" lines).
 * Run under ASan/UBSan (make clean && make check SANITIZE=1) to turn the
 * historical out-of-bounds accesses into hard failures.
 *
 * Nothing here needs root, a network interface or DNS. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "hping2.h"
#include "globals.h"
#include "ars.h"
#include "hex.h"
#include "hstring.h"
#include "adbuf.h"
#include "testutil.h"

#include "stub_send.h"

#define SADDR 0xc0a80106UL /* 192.168.1.6 */
#define DADDR 0xc0a80107UL /* 192.168.1.7 */

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static void test_memstr(void)
{
	char hay[] = "abc\0defSIGNxyz";

	TEST("memstr");
	/* Regression: needle length was stored in a 'char' and the loop
	 * bound was computed as haystack-needlesize+size, which reads past
	 * the buffer for needles longer than 127 bytes and for sizes smaller
	 * than the needle. */
	CHECK(memstr(hay, "SIGN", sizeof(hay)) == hay + 7);
	CHECK(memstr(hay, "SIGN", 10) == NULL);	/* needle crosses 'size' */
	CHECK(memstr(hay, "SIGN", 11) == hay + 7);	/* exactly fits */
	CHECK(memstr(hay, "zzz", sizeof(hay)) == NULL);
	CHECK(memstr(hay, "", 3) == hay);		/* empty needle */
	CHECK(memstr(hay, "abc", 2) == NULL);		/* size < needle */
	CHECK(memstr(hay, "abc", -1) == NULL);		/* negative size */
	{
		/* needle of 200 bytes: 'char needlesize' used to wrap negative */
		char big[300], needle[201];
		memset(big, 'a', sizeof(big));
		memset(needle, 'a', 200);
		needle[200] = '\0';
		CHECK(memstr(big, needle, sizeof(big)) == big);
		CHECK(memstr(big, needle, 199) == NULL);
	}
}

static void test_hex(void)
{
	unsigned char out[8];

	TEST("hextobin");
	memset(out, 0, sizeof(out));
	CHECK_EQ_INT(hextobin(out, "00ff7fA5", -1), 0);
	CHECK_EQ_INT(out[0], 0x00);
	CHECK_EQ_INT(out[1], 0xff);
	CHECK_EQ_INT(out[2], 0x7f);
	CHECK_EQ_INT(out[3], 0xa5);
	/* Regression: the lookup table was 'char', so the 255 "invalid"
	 * marker became -1 and invalid digits were silently accepted. */
	CHECK_EQ_INT(hextobin(out, "zz", -1), 1);
	CHECK_EQ_INT(hextobin(out, "0g", -1), 1);
	CHECK_EQ_INT(hextobin(out, "abc", -1), 1);	/* odd length */
}

static void test_hstring(void)
{
	char s1[] = "1,2,,3";
	char *tok[4];

	TEST("strisnum/strftok");
	CHECK(strisnum("123"));
	CHECK(strisnum(" -12 "));
	CHECK(!strisnum(""));
	CHECK(!strisnum("-"));
	CHECK(!strisnum("12a"));
	CHECK_EQ_INT(strftok(",", s1, tok, 4), 3);
	CHECK_EQ_STR(tok[0], "1");
	CHECK_EQ_STR(tok[1], "2");
	CHECK_EQ_STR(tok[2], "3");
}

static void test_adbuf(void)
{
	struct adbuf b;

	TEST("adbuf");
	CHECK_EQ_INT(adbuf_init(&b), 0);
	CHECK_EQ_INT(adbuf_printf(&b, "x=%d,", 42), 0);
	CHECK_EQ_STR(adbuf_ptr(&b), "x=42,");
	CHECK_EQ_INT(adbuf_rtrim(&b, 1), 0);
	CHECK_EQ_STR(adbuf_ptr(&b), "x=42");
	CHECK_EQ_INT(adbuf_rtrim(&b, 100), 0);	/* more than stored: no-op */
	CHECK_EQ_STR(adbuf_ptr(&b), "x=42");
	adbuf_free(&b);
	CHECK_EQ_INT(adbuf_init(&b), 0);
	CHECK_EQ_INT(adbuf_rtrim(&b, 1), 0);	/* empty buffer: no underflow */
	CHECK_EQ_STR(adbuf_ptr(&b), "");
	adbuf_free(&b);
}

static void test_cksum(void)
{
	/* RFC 1071 example: the header from RFC 1071 section 3 / common
	 * IPv4 header test vector. Checksum of this header must verify to 0. */
	unsigned char ip[20] = {
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
		0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7 };
	unsigned char odd[3] = { 0x01, 0x02, 0x03 };
	__u16 v;

	TEST("cksum");
	cfg.opt_badcksum = FALSE;
	CHECK_EQ_INT(cksum((__u16*)ip, 20), 0);		/* valid header */
	CHECK_EQ_INT(ars_cksum(ip, 20), 0);
	memcpy(&v, ip+10, 2); ip[10] = ip[11] = 0;
	CHECK_EQ_INT(cksum((__u16*)ip, 20), v);		/* recomputed */
	CHECK_EQ_INT(ars_cksum(ip, 20), v);
	CHECK_EQ_INT(ars_cksum(ip, 20), tu_cksum(ip, 20));
	/* odd length: the trailing byte is padded with zero */
	CHECK_EQ_INT(ars_cksum(odd, 3), tu_cksum(odd, 3));
	CHECK_EQ_INT(cksum((__u16*)odd, 3), tu_cksum(odd, 3));
	/* --badcksum deliberately corrupts the sum: it must stay possible */
	cfg.opt_badcksum = TRUE;
	CHECK(cksum((__u16*)ip, 20) != v);
	cfg.opt_badcksum = FALSE;

	TEST("ars_multi_cksum: odd sized chunks give the single buffer result");
	/* Regression: the trailing odd byte was fetched as a 16 bit word
	 * (one byte past the buffer) and the pending byte was combined
	 * with byte-order dependent shifts. */
	{
		unsigned char data[11] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
		struct mc_context mc;
		unsigned short whole = ars_cksum(data, 11);
		int split;

		CHECK_EQ_INT(whole, tu_cksum(data, 11));
		for (split = 0; split <= 11; split++) {
			ars_multi_cksum(&mc, ARS_MC_INIT, NULL, 0);
			ars_multi_cksum(&mc, ARS_MC_UPDATE, data, split);
			ars_multi_cksum(&mc, ARS_MC_UPDATE, data + split, 11 - split);
			CHECK_EQ_INT(ars_multi_cksum(&mc, ARS_MC_FINAL, NULL, 0), whole);
		}
		/* three chunks, all odd */
		ars_multi_cksum(&mc, ARS_MC_INIT, NULL, 0);
		ars_multi_cksum(&mc, ARS_MC_UPDATE, data, 3);
		ars_multi_cksum(&mc, ARS_MC_UPDATE, data + 3, 5);
		ars_multi_cksum(&mc, ARS_MC_UPDATE, data + 8, 3);
		CHECK_EQ_INT(ars_multi_cksum(&mc, ARS_MC_FINAL, NULL, 0), whole);
	}
}

static void test_rand_dest(void)
{
	unsigned char ra[4];

	TEST("parse_rand_dest");
	/* Regression: "%4[^.]" writes up to 4 characters plus the nul
	 * terminator into 4-byte arrays (stack overflow by one byte per
	 * octet, e.g. with "1234.x.x.x" or "255.255.255.255"). */
	CHECK_EQ_INT(parse_rand_dest("192.168.x.255", ra), 0);
	CHECK_EQ_INT(ra[0], 192);
	CHECK_EQ_INT(ra[1], 168);
	CHECK_EQ_INT(ra[3], 255);
	CHECK_EQ_INT(parse_rand_dest("255.255.255.255", ra), 0);
	CHECK_EQ_INT(ra[2], 255);
	CHECK_EQ_INT(parse_rand_dest("x.x.x.x", ra), 0);
	CHECK_EQ_INT(parse_rand_dest("1234.x.x.x", ra), -1);	/* > 255 */
	CHECK_EQ_INT(parse_rand_dest("10.x.x", ra), -1);	/* 3 octets */
	CHECK_EQ_INT(parse_rand_dest("10.a.x.x", ra), -1);	/* junk */
	CHECK_EQ_INT(parse_rand_dest("256.x.x.x", ra), -1);
}

/* ------------------------------------------------------------------ */
/* ARS: build via APD, then split and serialize again                  */
/* ------------------------------------------------------------------ */

/* Build a packet from an APD description. Returns malloc()ed bytes. */
static unsigned char *build_apd(const char *apd, size_t *size)
{
	struct ars_packet p;
	unsigned char *pkt = NULL;
	char *copy = strdup(apd);

	ars_init(&p);
	if (ars_d_build(&p, copy) != -ARS_OK) {
		fprintf(stderr, "build_apd(%s): %s\n", apd, p.p_error);
		free(copy);
		ars_destroy(&p);
		return NULL;
	}
	if (ars_compile(&p) != -ARS_OK ||
	    ars_build_packet(&p, &pkt, size) != -ARS_OK) {
		fprintf(stderr, "build_apd(%s): compile: %s\n", apd, p.p_error);
		pkt = NULL;
	}
	ars_destroy(&p);
	free(copy);
	return pkt;
}

/* Split 'pkt' and return its APD description (static buffer),
 * NULL on split error. */
static const char *describe(const unsigned char *pkt, size_t size, int hexdata,
			    int *layers, int *flags_or)
{
	static char d[8192];
	struct ars_packet p;
	int j;

	ars_init(&p);
	if (hexdata)
		ars_set_option(&p, ARS_OPT_RAPD_HEXDATA);
	if (ars_split_packet((void*)pkt, size, 0, &p) != -ARS_OK) {
		ars_destroy(&p);
		return NULL;
	}
	if (layers) *layers = p.p_layer_nr;
	if (flags_or) {
		*flags_or = 0;
		for (j = 0; j < p.p_layer_nr; j++)
			*flags_or |= p.p_layer[j].l_flags;
	}
	if (ars_d_from_ars(d, sizeof(d), &p) != -ARS_OK) {
		ars_destroy(&p);
		return NULL;
	}
	ars_destroy(&p);
	return d;
}

static void test_apd_build_vectors(void)
{
	unsigned char *pkt;
	size_t size;
	unsigned short ck;
	unsigned char seg[20];

	TEST("apd build: ip+tcp vector");
	pkt = build_apd("ip(saddr=192.168.1.6,daddr=192.168.1.7,ttl=64,id=0x1234)"
			"+tcp(sport=1234,dport=80,seq=1000,ack=2000,flags=s,win=512)", &size);
	CHECK(pkt != NULL);
	if (!pkt) return;
	CHECK_EQ_INT(size, 40);
	CHECK_EQ_INT(pkt[0], 0x45);
	CHECK_EQ_INT((pkt[2] << 8) | pkt[3], 40);	/* tot_len */
	CHECK_EQ_INT(pkt[9], 6);			/* proto */
	CHECK_EQ_INT(tu_cksum(pkt, 20), 0);		/* IP cksum valid */
	CHECK_EQ_INT(pkt[20+13], 0x02);			/* SYN */
	CHECK_EQ_INT(pkt[20+12] >> 4, 5);		/* data offset */
	/* independent TCP checksum */
	memcpy(seg, pkt+20, 20);
	memcpy(&ck, seg+16, 2); seg[16] = seg[17] = 0;
	CHECK_EQ_INT(ck, tu_l4_cksum(SADDR, DADDR, 6, seg, 20));
	free(pkt);

	TEST("apd build: explicit fields are kept (bad checksum on purpose)");
	pkt = build_apd("ip(saddr=192.168.1.6,daddr=192.168.1.7,cksum=0x1111,totlen=99)"
			"+udp(sport=1,dport=2,cksum=0)", &size);
	CHECK(pkt != NULL);
	if (!pkt) return;
	CHECK_EQ_INT((pkt[2] << 8) | pkt[3], 99);
	CHECK_EQ_INT(pkt[10], 0x11);
	CHECK_EQ_INT(pkt[11], 0x11);
	CHECK_EQ_INT(pkt[26] | pkt[27], 0);		/* udp cksum 0 kept */
	free(pkt);

	TEST("apd build: tcp options padding and tcp.ts values");
	/* Regression: tcp.ts had a bogus setter that accepted any field and
	 * did nothing; rapd emitted 'tcp.timestamp' which the parser rejected. */
	pkt = build_apd("ip(saddr=1.2.3.4,daddr=5.6.7.8)+tcp(dport=80)"
			"+tcp.mss(size=1460)+tcp.ts(val=0x01020304,ecr=0x0a0b0c0d)", &size);
	CHECK(pkt != NULL);
	if (!pkt) return;
	/* mss(4) + ts(10) = 14 -> padded to 16 */
	CHECK_EQ_INT(size, 20 + 20 + 16);
	CHECK_EQ_INT(pkt[20+12] >> 4, 9);
	CHECK_EQ_INT(pkt[40], 2);			/* mss kind */
	CHECK_EQ_INT(pkt[44], 8);			/* ts kind */
	CHECK_EQ_INT(pkt[45], 10);
	CHECK_EQ_INT(pkt[46], 0x01);
	CHECK_EQ_INT(pkt[49], 0x04);
	CHECK_EQ_INT(pkt[50], 0x0a);
	CHECK_EQ_INT(pkt[53], 0x0d);
	CHECK_EQ_INT(pkt[54], 1);			/* NOP padding */
	CHECK_EQ_INT(pkt[55], 1);
	free(pkt);

	TEST("apd build: aliases tcp.timestamp / tcp.echoreq");
	pkt = build_apd("ip(saddr=1.2.3.4,daddr=5.6.7.8)+tcp(dport=80)"
			"+tcp.timestamp(val=1,ecr=2)+tcp.echoreq(info=7)", &size);
	CHECK(pkt != NULL);
	free(pkt);

	TEST("apd build: unknown tcp.ts field is an error");
	{
		struct ars_packet p;
		char d[] = "ip(saddr=1.2.3.4,daddr=5.6.7.8)+tcp.ts(bogus=1)";
		ars_init(&p);
		CHECK(ars_d_build(&p, d) != -ARS_OK);
		ars_destroy(&p);
	}

	TEST("apd build: hex/str data decoding");
	pkt = build_apd("ip(saddr=1.2.3.4,daddr=5.6.7.8)+data(hex=00ff10)", &size);
	CHECK(pkt != NULL);
	if (pkt) {
		CHECK_EQ_INT(size, 23);
		CHECK_EQ_INT(pkt[20], 0x00);
		CHECK_EQ_INT(pkt[21], 0xff);
		CHECK_EQ_INT(pkt[22], 0x10);
		free(pkt);
	}
	pkt = build_apd("ip(saddr=1.2.3.4,daddr=5.6.7.8)+data(str=a\\41b\\zz)", &size);
	CHECK(pkt != NULL);
	if (pkt) {
		/* \41 is 'A'; "\zz" is not a hex escape and stays literal */
		CHECK_EQ_INT(size, 20 + 6);
		CHECK_MEM_EQ(pkt+20, "aAb\\zz", 6);
		free(pkt);
	}
	/* Regression: invalid hex digits were accepted (table init bug) */
	{
		struct ars_packet p;
		char d1[] = "ip(saddr=1.2.3.4,daddr=5.6.7.8)+data(hex=zz)";
		char d2[] = "ip(saddr=1.2.3.4,daddr=5.6.7.8)+data(hex=abc)";
		ars_init(&p);
		CHECK(ars_d_build(&p, d1) != -ARS_OK);
		ars_destroy(&p);
		ars_init(&p);
		CHECK(ars_d_build(&p, d2) != -ARS_OK);
		ars_destroy(&p);
	}

	TEST("apd build: tcp without ip must not crash the checksum compiler");
	/* Regression: ars_udptcp_cksum() searched the IP layer starting at
	 * layer-1 == -1 (out of bounds read of p_layer[-1]). */
	{
		struct ars_packet p;
		char d[] = "tcp(dport=80)";
		ars_init(&p);
		CHECK_EQ_INT(ars_d_build(&p, d), -ARS_OK);
		CHECK(ars_compile(&p) != -ARS_OK);
		ars_destroy(&p);
	}

	TEST("apd build: ip.sec tcc lands in the tcc field");
	pkt = build_apd("ip(saddr=1.2.3.4,daddr=5.6.7.8)+ip.sec(hrest=1122,tcc=aabbcc)+icmp()", &size);
	CHECK(pkt != NULL);
	if (pkt) {
		/* option at 20: kind(130) len(11) s(2) c(2) h(2) tcc(3) */
		CHECK_EQ_INT(pkt[20], 130);
		CHECK_EQ_INT(pkt[26], 0x11);
		CHECK_EQ_INT(pkt[27], 0x22);
		CHECK_EQ_INT(pkt[28], 0xaa);
		CHECK_EQ_INT(pkt[29], 0xbb);
		CHECK_EQ_INT(pkt[30], 0xcc);
		free(pkt);
	}
}

static void test_split_roundtrip(void)
{
	unsigned char *pkt;
	size_t size;
	const char *d;
	int layers, flags;

	TEST("split: ip+tcp+data round trip");
	pkt = build_apd("ip(saddr=192.168.1.6,daddr=192.168.1.7,ttl=64,id=1)"
			"+tcp(sport=1234,dport=80,seq=1,ack=2,flags=sa,win=512)"
			"+data(str=hello)", &size);
	CHECK(pkt != NULL);
	if (!pkt) return;
	d = describe(pkt, size, 0, &layers, &flags);
	CHECK(d != NULL);
	CHECK_EQ_INT(layers, 3);
	CHECK_EQ_INT(flags, 0);		/* checksums verified, not truncated */
	if (d) {
		CHECK(strstr(d, "ip(") == d);
		CHECK(strstr(d, "saddr=192.168.1.6") != NULL);
		CHECK(strstr(d, "+tcp(sport=1234,dport=80") != NULL);
		CHECK(strstr(d, "flags=sa") != NULL);
		CHECK(strstr(d, "+data(str=hello)") != NULL);
		/* the description must parse and build the same bytes */
		{
			unsigned char *pkt2;
			size_t size2;
			char *copy = strdup(d);
			/* strip the checksums so they are recomputed */
			pkt2 = build_apd(copy, &size2);
			CHECK(pkt2 != NULL);
			if (pkt2) {
				CHECK_EQ_INT(size2, size);
				CHECK_MEM_EQ(pkt2, pkt, size);
				free(pkt2);
			}
			free(copy);
		}
	}
	free(pkt);

	TEST("split: ip options, tcp options (incl. sack-permitted) round trip");
	pkt = build_apd("ip(saddr=192.168.1.6,daddr=192.168.1.7)+ip.rr(data=10.0.0.1/10.0.0.2)"
			"+tcp(dport=80,flags=s)+tcp.mss(size=1460)+tcp.sackperm()+tcp.ts(val=5,ecr=6)+tcp.wscale(shift=7)", &size);
	CHECK(pkt != NULL);
	if (!pkt) return;
	d = describe(pkt, size, 0, &layers, &flags);
	CHECK(d != NULL);
	CHECK_EQ_INT(flags, 0);
	if (d) {
		/* Regression: sack-permitted was split as a 1 byte option,
		 * so the following options were misparsed. */
		CHECK(strstr(d, "+tcp.sackperm()+") != NULL);
		CHECK(strstr(d, "+tcp.ts(val=5,ecr=6)+") != NULL);
		CHECK(strstr(d, "+tcp.wscale(shift=7)") != NULL);
		/* the whole route buffer is described, not only up to ptr */
		CHECK(strstr(d, "+ip.rr(ptr=12,data=10.0.0.1/10.0.0.2/0.0.0.0") != NULL);
		/* Regression: the window scale shift byte went through htons() */
		CHECK(strstr(d, "+tcp.wscale(shift=7)") != NULL);
	}
	free(pkt);

	TEST("split: icmp error quoting ip+udp");
	pkt = build_apd("ip(saddr=10.0.0.1,daddr=10.0.0.2)+icmp(type=3,code=3)"
			"+ip(saddr=10.0.0.2,daddr=10.0.0.1)+udp(sport=53,dport=1024)+data(str=xy)", &size);
	CHECK(pkt != NULL);
	if (!pkt) return;
	d = describe(pkt, size, 0, &layers, &flags);
	CHECK(d != NULL);
	CHECK_EQ_INT(layers, 5);
	if (d)
		CHECK(strstr(d, "+icmp(type=3,code=3,unused=0)+ip(") != NULL);
	free(pkt);
}

static void test_split_malformed(void)
{
	unsigned char buf[128];
	const char *d;
	int layers, flags, hlen, i;

	TEST("split: tot_len smaller than the IP header must not underflow");
	/* Regression: size = MIN(size, tot_len) followed by size -= 20
	 * wrapped size_t to ~2^64 and the next state read far out of bounds
	 * (ICMP path even alloca()ed that size). */
	memset(buf, 0, sizeof(buf));
	tu_build_ip(buf, 0, 10, 1, SADDR, DADDR);	/* proto ICMP, totlen 10 */
	buf[20] = 8;					/* an ICMP echo follows */
	d = describe(buf, 48, 0, &layers, &flags);
	CHECK(d != NULL);
	CHECK_EQ_INT(layers, 1);			/* only the IP header */

	TEST("split: IHL < 5");
	memset(buf, 0, sizeof(buf));
	tu_build_ip(buf, 0, 40, 6, SADDR, DADDR);
	buf[0] = 0x42;					/* ihl = 2 */
	d = describe(buf, 40, 0, &layers, &flags);
	CHECK(d != NULL);
	CHECK(flags & ARS_SPLIT_FBADCKSUM);
	CHECK_EQ_INT(layers, 2);			/* ip + data */

	TEST("split: truncated TCP header (fewer than 20 bytes)");
	/* Regression: th_off was read before checking the size, and the
	 * checksum hack wrote th_sum into a layer shorter than 18 bytes
	 * (heap overflow). Sizes 1..19 are all tried. */
	for (i = 1; i < 20; i++) {
		memset(buf, 0, sizeof(buf));
		hlen = tu_build_ip(buf, 0, 20 + i, 6, SADDR, DADDR);
		tu_build_tcp(buf + hlen, 1, 2, 0x02, 5);
		d = describe(buf, hlen + i, 0, &layers, &flags);
		CHECK(d != NULL);
		CHECK(flags & ARS_SPLIT_FTRUNC);
		CHECK_EQ_INT(layers, 2);
	}

	TEST("split: truncated UDP header");
	for (i = 1; i < 8; i++) {
		memset(buf, 0, sizeof(buf));
		hlen = tu_build_ip(buf, 0, 20 + i, 17, SADDR, DADDR);
		d = describe(buf, hlen + i, 0, &layers, &flags);
		CHECK(d != NULL);
		CHECK(flags & ARS_SPLIT_FTRUNC);
	}

	TEST("split: TCP data offset < 5 and > captured");
	memset(buf, 0, sizeof(buf));
	hlen = tu_build_ip(buf, 0, 40, 6, SADDR, DADDR);
	tu_build_tcp(buf + hlen, 1, 2, 0x02, 2);	/* doff = 2 */
	d = describe(buf, 40, 0, &layers, &flags);
	CHECK(d != NULL);
	CHECK(flags & ARS_SPLIT_FBADCKSUM);
	memset(buf, 0, sizeof(buf));
	hlen = tu_build_ip(buf, 0, 40, 6, SADDR, DADDR);
	tu_build_tcp(buf + hlen, 1, 2, 0x02, 15);	/* doff = 15 (60 bytes) */
	d = describe(buf, 40, 0, &layers, &flags);
	CHECK(d != NULL);
	CHECK(flags & ARS_SPLIT_FTRUNC);

	TEST("split: zero-length and one-byte-only TCP options terminate");
	/* Regression: a TCP option with len 0 (or an option whose length
	 * byte is missing) looped forever / read one byte past the buffer. */
	memset(buf, 0, sizeof(buf));
	hlen = tu_build_ip(buf, 0, 44, 6, SADDR, DADDR);
	tu_build_tcp(buf + hlen, 1, 2, 0x02, 6);	/* 4 bytes of options */
	buf[hlen+20] = 2; buf[hlen+21] = 0;		/* mss with len 0 */
	buf[hlen+22] = 3; buf[hlen+23] = 0;
	d = describe(buf, 44, 0, &layers, &flags);
	CHECK(d != NULL);
	/* option area ends exactly with a kind byte, no length byte */
	memset(buf, 0, sizeof(buf));
	hlen = tu_build_ip(buf, 0, 44, 6, SADDR, DADDR);
	tu_build_tcp(buf + hlen, 1, 2, 0x02, 6);
	buf[hlen+20] = 1; buf[hlen+21] = 1; buf[hlen+22] = 1; buf[hlen+23] = 2;
	d = describe(buf, 44, 0, &layers, &flags);
	CHECK(d != NULL);
	CHECK(flags & ARS_SPLIT_FTRUNC);

	TEST("split: IP option with len 0 / missing length byte");
	memset(buf, 0, sizeof(buf));
	buf[20] = 7; buf[21] = 0; buf[22] = 0; buf[23] = 0;	/* rr len 0 */
	hlen = tu_build_ip(buf, 4, 24, 6, SADDR, DADDR);
	d = describe(buf, 24, 0, &layers, &flags);
	CHECK(d != NULL);
	memset(buf, 0, sizeof(buf));
	buf[20] = 1; buf[21] = 1; buf[22] = 1; buf[23] = 7;	/* rr kind only */
	hlen = tu_build_ip(buf, 4, 24, 6, SADDR, DADDR);
	d = describe(buf, 24, 0, &layers, &flags);
	CHECK(d != NULL);

	TEST("split: options longer than the rapd structures");
	/* Regression: rapd copied l_size bytes into a 40/34 byte stack
	 * struct; an RR option claiming len=255 in a 60 byte header, or a
	 * SACK option with len 255, overflowed the stack. */
	memset(buf, 0, sizeof(buf));
	buf[20] = 7; buf[21] = 39; buf[22] = 4;			/* rr, len 39 */
	buf[59] = 0;
	hlen = tu_build_ip(buf, 40, 60, 6, SADDR, DADDR);
	d = describe(buf, 60, 0, &layers, &flags);
	CHECK(d != NULL);
	memset(buf, 0, sizeof(buf));
	buf[20] = 7; buf[21] = 255; buf[22] = 255;		/* rr, len 255 */
	hlen = tu_build_ip(buf, 40, 60, 6, SADDR, DADDR);
	d = describe(buf, 60, 0, &layers, &flags);
	CHECK(d != NULL);
	memset(buf, 0, sizeof(buf));
	buf[20] = 68; buf[21] = 255; buf[22] = 255; buf[23] = 0xff; /* ts, len 255 */
	hlen = tu_build_ip(buf, 40, 60, 6, SADDR, DADDR);
	d = describe(buf, 60, 0, &layers, &flags);
	CHECK(d != NULL);
	memset(buf, 0, sizeof(buf));
	hlen = tu_build_ip(buf, 0, 60, 6, SADDR, DADDR);
	tu_build_tcp(buf + hlen, 1, 2, 0x02, 15);
	buf[hlen+20] = 5; buf[hlen+21] = 255;			/* sack, len 255 */
	d = describe(buf, 60, 0, &layers, &flags);
	CHECK(d != NULL);
	memset(buf, 0, sizeof(buf));
	hlen = tu_build_ip(buf, 0, 60, 6, SADDR, DADDR);
	tu_build_tcp(buf + hlen, 1, 2, 0x02, 15);
	buf[hlen+20] = 99; buf[hlen+21] = 255;			/* unknown, len 255 */
	d = describe(buf, 60, 0, &layers, &flags);
	CHECK(d != NULL);
	if (d) CHECK(strstr(d, "tcp.unknown(hex=63ff") != NULL);

	TEST("split: empty and one byte packets");
	d = describe(buf, 0, 0, &layers, &flags);
	CHECK(d != NULL);
	d = describe(buf, 1, 0, &layers, &flags);
	CHECK(d != NULL);
	CHECK(flags & ARS_SPLIT_FTRUNC);

	TEST("split: ICMP error with a truncated quoted header");
	memset(buf, 0, sizeof(buf));
	hlen = tu_build_ip(buf, 0, 30, 1, SADDR, DADDR);
	buf[20] = 3; buf[21] = 3;			/* dest unreach */
	buf[28] = 0x45;					/* 2 bytes of quoted IP */
	d = describe(buf, 30, 0, &layers, &flags);
	CHECK(d != NULL);
	CHECK(flags & ARS_SPLIT_FTRUNC);
}

/* ------------------------------------------------------------------ */
/* display_ipopt()                                                     */
/* ------------------------------------------------------------------ */

static char *capture_stdout(void (*fn)(char*), char *arg, char *out, size_t outlen)
{
	FILE *tmp = tmpfile();
	int saved = dup(1);
	size_t n;

	fflush(stdout);
	dup2(fileno(tmp), 1);
	fn(arg);
	fflush(stdout);
	dup2(saved, 1);
	close(saved);
	rewind(tmp);
	n = fread(out, 1, outlen - 1, tmp);
	out[n] = '\0';
	fclose(tmp);
	return out;
}

static void test_display_ipopt(void)
{
	unsigned char buf[64];
	char out[1024];

	TEST("display_ipopt: valid record route");
	memset(buf, 0, sizeof(buf));
	buf[20] = IPOPT_RR; buf[21] = 11; buf[22] = 12;	/* 2 addresses */
	tu_put32(buf+23, 0x0a000001UL);
	tu_put32(buf+27, 0x0a000002UL);
	buf[31] = IPOPT_EOL;
	tu_build_ip(buf, 12, 32, 6, SADDR, DADDR);
	capture_stdout(display_ipopt, (char*)buf, out, sizeof(out));
	CHECK(strstr(out, "RR: \t10.0.0.1\n\t10.0.0.2\n") != NULL);
	/* the same route again prints "(same route)" */
	capture_stdout(display_ipopt, (char*)buf, out, sizeof(out));
	CHECK(strstr(out, "(same route)") != NULL);

	TEST("display_ipopt: RR with length/pointer larger than the header");
	/* Regression: the byte count derived from the option's own fields
	 * was used for memcpy() into the 40 byte old_rr buffer and to walk
	 * the packet, without any bound: a len/ptr of 255 overflowed. */
	memset(buf, 0, sizeof(buf));
	buf[20] = IPOPT_RR; buf[21] = 255; buf[22] = 255;
	tu_build_ip(buf, 40, 60, 6, SADDR, DADDR);
	capture_stdout(display_ipopt, (char*)buf, out, sizeof(out));
	CHECK(strstr(out, "[|ipopt]") != NULL);
	memset(buf, 0, sizeof(buf));
	buf[20] = IPOPT_RR; buf[21] = 39; buf[22] = 255;	/* ptr > len */
	tu_build_ip(buf, 40, 60, 6, SADDR, DADDR);
	capture_stdout(display_ipopt, (char*)buf, out, sizeof(out));
	CHECK(strstr(out, "RR: ") != NULL);
	/* len 39 -> 9 addresses printed, the 10th does not exist */
	{
		int n = 0; const char *p = out;
		while ((p = strstr(p, "0.0.0.0")) != NULL) { n++; p++; }
		CHECK_EQ_INT(n, 9);
	}

	TEST("display_ipopt: LSRR/SSRR and unknown options");
	memset(buf, 0, sizeof(buf));
	buf[20] = IPOPT_LSRR; buf[21] = 7; buf[22] = 4;
	tu_put32(buf+23, 0x0a000009UL);
	buf[27] = IPOPT_NOP; buf[28] = 0x99; buf[29] = 3; buf[30] = 0; buf[31] = IPOPT_EOL;
	tu_build_ip(buf, 12, 32, 6, SADDR, DADDR);
	capture_stdout(display_ipopt, (char*)buf, out, sizeof(out));
	CHECK(strstr(out, "LSRR: \t10.0.0.9\n") != NULL);
	CHECK(strstr(out, "NOP\n") != NULL);
	CHECK(strstr(out, "unknown option 99\n") != NULL);
	/* len byte of 1 (never makes progress) */
	memset(buf, 0, sizeof(buf));
	buf[20] = 0x99; buf[21] = 1; buf[22] = 0x99; buf[23] = 1;
	tu_build_ip(buf, 4, 24, 6, SADDR, DADDR);
	capture_stdout(display_ipopt, (char*)buf, out, sizeof(out));
	CHECK(strstr(out, "[|ipopt]") != NULL);

	TEST("display_ipopt: no options");
	memset(buf, 0, sizeof(buf));
	tu_build_ip(buf, 0, 20, 6, SADDR, DADDR);
	capture_stdout(display_ipopt, (char*)buf, out, sizeof(out));
	CHECK_EQ_STR(out, "");
}

/* ------------------------------------------------------------------ */
/* send_icmp_other(): quoted headers copied from stack/heap objects     */
/* ------------------------------------------------------------------ */

static void test_send_icmp_other(void)
{
	extern int send_icmp_other(void);
	unsigned char *p;

	TEST("send_icmp_other: quoted IP+UDP header and data");
	/* Regression: memcpy(packet+8, &icmp_ip, left_space) copied
	 * IPHDR_SIZE+UDPHDR_SIZE+data_size bytes out of a 20 byte stack
	 * struct (and the same for the 8 byte UDP header). */
	cfg.opt_icmptype = ICMP_TIME_EXCEEDED;
	cfg.opt_icmpcode = 0;
	cfg.icmp_cksum = -1;
	cfg.data_size = 16;
	cfg.opt_sign = FALSE; cfg.opt_datafromfile = FALSE; cfg.opt_listenmode = FALSE;
	ctx.icmp_ip_src.sin_addr.s_addr = htonl(0x01020304UL);
	ctx.icmp_ip_dst.sin_addr.s_addr = htonl(0x05060708UL);
	cfg.icmp_ip_srcport = 1111;
	cfg.icmp_ip_dstport = 2222;
	stub_send_calls = 0;
	send_icmp_other();
	CHECK_EQ_INT(stub_send_calls, 1);
	CHECK_EQ_INT(stub_last_size, 8 + 20 + 8 + 16);
	p = stub_last_packet;
	CHECK_EQ_INT(p[0], ICMP_TIME_EXCEEDED);
	CHECK_EQ_INT(p[8], 0x45);			/* quoted IP */
	CHECK_EQ_INT(p[8+9], 6);			/* proto TCP default */
	CHECK_EQ_INT(tu_cksum(p+8, 20), 0);		/* quoted IP cksum ok */
	CHECK_EQ_INT((p[28] << 8) | p[29], 1111);	/* quoted sport */
	CHECK_EQ_INT((p[30] << 8) | p[31], 2222);	/* quoted dport */
	CHECK_EQ_INT(p[36], 'X');			/* data filler */
	CHECK_EQ_INT(p[51], 'X');
	CHECK_EQ_INT(tu_cksum(p, stub_last_size), 0);	/* ICMP cksum ok */
	cfg.data_size = 0;
	stub_send_calls = 0;
	send_icmp_other();
	CHECK_EQ_INT(stub_last_size, 8 + 20 + 8);
}

/* ------------------------------------------------------------------ */
/* pcap_recv(): capture length vs destination buffer                   */
/* ------------------------------------------------------------------ */

static const char *write_fixture(int dlt, const unsigned char *pkt, size_t len, int copies)
{
	static char path[256];
	pcap_t *dead = pcap_open_dead(dlt, 65535);
	pcap_dumper_t *dump;
	struct pcap_pkthdr h;
	int i;

	snprintf(path, sizeof(path), "/tmp/hping-test-%ld-%d.pcap", (long)getpid(), dlt);
	dump = pcap_dump_open(dead, path);
	if (!dump) {
		fprintf(stderr, "pcap_dump_open: %s\n", pcap_geterr(dead));
		exit(2);
	}
	memset(&h, 0, sizeof(h));
	h.caplen = h.len = len;
	for (i = 0; i < copies; i++) {
		h.ts.tv_sec = i;
		pcap_dump((u_char*)dump, &h, pkt);
	}
	pcap_dump_close(dump);
	pcap_close(dead);
	return path;
}

static void test_pcap_recv(void)
{
	unsigned char pkt[100], buf[100];
	const char *path;
	char err[PCAP_ERRBUF_SIZE];
	int n;

	TEST("pcap_recv: frame larger than the buffer is truncated");
	/* Regression: the clamped size was computed but memcpy() still
	 * copied the full caplen into the smaller buffer. */
	memset(pkt, 0xab, sizeof(pkt));
	path = write_fixture(DLT_RAW, pkt, 100, 2);
	ctx.pcapfp = pcap_open_offline(path, err);
	CHECK(ctx.pcapfp != NULL);
	if (!ctx.pcapfp) return;
	memset(buf, 0, sizeof(buf));
	n = pcap_recv((char*)buf, 40);
	CHECK_EQ_INT(n, 40);
	CHECK_EQ_INT(buf[39], 0xab);
	CHECK_EQ_INT(buf[40], 0);			/* untouched */
	n = pcap_recv((char*)buf, 100);
	CHECK_EQ_INT(n, 100);
	n = pcap_recv((char*)buf, 100);
	CHECK_EQ_INT(n, -1);				/* end of savefile */
	CHECK_EQ_INT(read_packet(buf, 100), -1);
	pcap_close(ctx.pcapfp);
	ctx.pcapfp = NULL;
	unlink(path);
}

/* ------------------------------------------------------------------ */
/* IPv6: build, dissect, checksums (offline slice)                     */
/* ------------------------------------------------------------------ */

#define V6SRC "2001:db8::1"
#define V6DST "2001:db8::2"

static void test_ipv6_vectors(void)
{
	unsigned char *pkt;
	size_t size;
	const char *d;
	int layers, flags;
	unsigned short ck;
	unsigned char seg[64], buf[128];

	TEST("ipv6: header fields on the wire (RFC 8200 layout)");
	pkt = build_apd("ip6(saddr=2001:db8::1,daddr=2001:db8::2,tclass=0x20,"
			"flow=0x12345,hlim=7)+icmp6(type=128,id=7,seq=3)+data(str=hello)", &size);
	CHECK(pkt != NULL);
	if (!pkt) return;
	CHECK_EQ_INT(size, 40 + 8 + 5);
	CHECK_EQ_INT(pkt[0] >> 4, 6);			/* version */
	/* version|tclass|flow = 6, 0x20, 0x12345 */
	CHECK_EQ_INT(((pkt[0] & 0x0f) << 4) | (pkt[1] >> 4), 0x20);
	CHECK_EQ_INT(((pkt[1] & 0x0f) << 16) | (pkt[2] << 8) | pkt[3], 0x12345);
	CHECK_EQ_INT((pkt[4] << 8) | pkt[5], 13);	/* payload length */
	CHECK_EQ_INT(pkt[6], 58);			/* next header: ICMPv6 */
	CHECK_EQ_INT(pkt[7], 7);			/* hop limit */
	{
		unsigned char a[16];
		tu_pton6(V6SRC, a);
		CHECK_MEM_EQ(pkt + 8, a, 16);
		tu_pton6(V6DST, a);
		CHECK_MEM_EQ(pkt + 24, a, 16);
	}

	TEST("ipv6: the ICMPv6 checksum covers the pseudo header (RFC 4443 2.3)");
	/* independent computation: the ICMPv6 message with a zero checksum */
	memcpy(seg, pkt + 40, 13);
	seg[2] = seg[3] = 0;
	ck = tu_l4_cksum6(V6SRC, V6DST, 58, seg, 13);
	CHECK_MEM_EQ(pkt + 42, &ck, 2);
	/* and it really differs from the ICMPv4-style sum (no pseudo header) */
	CHECK(tu_cksum(seg, 13) != ck);
	free(pkt);

	TEST("ipv6: TCP checksum uses the IPv6 pseudo header");
	pkt = build_apd("ip6(saddr=2001:db8::1,daddr=2001:db8::2)"
			"+tcp(sport=1234,dport=80,seq=1000,ack=2000,flags=s,win=512)", &size);
	CHECK(pkt != NULL);
	if (!pkt) return;
	CHECK_EQ_INT(size, 60);
	CHECK_EQ_INT(pkt[6], 6);			/* next header: TCP */
	CHECK_EQ_INT((pkt[4] << 8) | pkt[5], 20);
	memcpy(seg, pkt + 40, 20);
	seg[16] = seg[17] = 0;
	ck = tu_l4_cksum6(V6SRC, V6DST, 6, seg, 20);
	CHECK_MEM_EQ(pkt + 40 + 16, &ck, 2);
	free(pkt);

	TEST("ipv6: UDP checksum and length");
	pkt = build_apd("ip6(saddr=2001:db8::1,daddr=2001:db8::2)"
			"+udp(sport=53,dport=1024)+data(str=xy)", &size);
	CHECK(pkt != NULL);
	if (!pkt) return;
	CHECK_EQ_INT(size, 40 + 8 + 2);
	CHECK_EQ_INT(pkt[6], 17);
	CHECK_EQ_INT((pkt[40+4] << 8) | pkt[40+5], 10);	/* UDP length */
	memcpy(seg, pkt + 40, 10);
	seg[6] = seg[7] = 0;
	ck = tu_l4_cksum6(V6SRC, V6DST, 17, seg, 10);
	CHECK_MEM_EQ(pkt + 40 + 6, &ck, 2);
	free(pkt);

	TEST("ipv6: dissect a packet built independently, byte-exact round trip");
	memset(buf, 0, sizeof(buf));
	{
		int hlen = tu_build_ip6(buf, 0, 0, 13, 58, V6SRC, V6DST);
		unsigned char *ic = buf + hlen;
		ic[0] = 128; ic[1] = 0;			/* echo request */
		tu_put16(ic + 4, 7); tu_put16(ic + 6, 3);
		memcpy(ic + 8, "hello", 5);
		ck = tu_l4_cksum6(V6SRC, V6DST, 58, ic, 13);
		memcpy(ic + 2, &ck, 2);
		d = describe(buf, hlen + 13, 0, &layers, &flags);
	}
	CHECK(d != NULL);
	CHECK_EQ_INT(layers, 3);			/* ip6 + icmp6 + data */
	CHECK_EQ_INT(flags, 0);				/* checksum verified */
	if (d) {
		CHECK(strstr(d, "ip6(ver=6,") == d);
		CHECK(strstr(d, "saddr=2001:db8::1") != NULL);
		CHECK(strstr(d, "daddr=2001:db8::2") != NULL);
		CHECK(strstr(d, "nh=58") != NULL);
		CHECK(strstr(d, "+icmp6(type=128,code=0,") != NULL);
		CHECK(strstr(d, "id=7,seq=3") != NULL);
		CHECK(strstr(d, "+data(str=hello)") != NULL);
		/* the description rebuilds the same bytes */
		{
			unsigned char *again;
			size_t asize;
			char *copy = strdup(d);
			again = build_apd(copy, &asize);
			CHECK(again != NULL);
			if (again) {
				CHECK_EQ_INT(asize, 53);
				CHECK_MEM_EQ(again, buf, 53);
				free(again);
			}
			free(copy);
		}
	}

	TEST("ipv6: a bad ICMPv6 checksum is flagged");
	buf[42] ^= 0xff;
	d = describe(buf, 53, 0, &layers, &flags);
	CHECK(d != NULL);
	CHECK(flags & ARS_SPLIT_FBADCKSUM);
	buf[42] ^= 0xff;

	TEST("ipv6: truncated header and truncated ICMPv6");
	{
		int i;
		/* a header shorter than 40 bytes is truncated */
		for (i = 1; i < 40; i++) {
			d = describe(buf, i, 0, &layers, &flags);
			CHECK(d != NULL);
			CHECK(flags & ARS_SPLIT_FTRUNC);
		}
		/* exactly 40 bytes: a complete header and nothing after it */
		d = describe(buf, 40, 0, &layers, &flags);
		CHECK(d != NULL);
		CHECK_EQ_INT(layers, 1);
		CHECK_EQ_INT(flags, 0);
		/* 41..47: the ICMPv6 header itself is truncated */
		for (i = 41; i < 48; i++) {
			d = describe(buf, i, 0, &layers, &flags);
			CHECK(d != NULL);
			CHECK(flags & ARS_SPLIT_FTRUNC);
		}
	}

	TEST("ipv6: payload_len shorter than what is captured trims the packet");
	memset(buf, 0, sizeof(buf));
	tu_build_ip6(buf, 0, 0, 0, 58, V6SRC, V6DST);	/* plen 0 */
	buf[40] = 128;
	d = describe(buf, 60, 0, &layers, &flags);
	CHECK(d != NULL);
	CHECK_EQ_INT(layers, 1);			/* only the header */

	TEST("ipv6: an extension header is kept as data, not misparsed");
	memset(buf, 0, sizeof(buf));
	tu_build_ip6(buf, 0, 0, 8, 44, V6SRC, V6DST);	/* 44 = Fragment */
	buf[40] = 58; buf[41] = 0;			/* fragment header */
	d = describe(buf, 48, 0, &layers, &flags);
	CHECK(d != NULL);
	CHECK(ars_ip6_is_extension(44) && ars_ip6_is_extension(0) &&
	      ars_ip6_is_extension(43) && ars_ip6_is_extension(60));
	CHECK(!ars_ip6_is_extension(58) && !ars_ip6_is_extension(6));
	if (d) {
		CHECK(strstr(d, "ip6(") == d);
		CHECK(strstr(d, "+data(") != NULL);	/* the 8 bytes are kept */
		CHECK(strstr(d, "icmp6(") == NULL);	/* not dissected as ICMPv6 */
	}

	TEST("ipv6: IPv4 dissection is unaffected (version nibble dispatch)");
	memset(buf, 0, sizeof(buf));
	{
		int hlen = tu_build_ip(buf, 0, 40, 6, SADDR, DADDR);
		tu_build_tcp(buf + hlen, 1, 2, 0x02, 5);
		d = describe(buf, 40, 0, &layers, &flags);
	}
	CHECK(d != NULL);
	if (d) CHECK(strstr(d, "ip(ihl=0x5,ver=0x4") == d);

	TEST("ipv6: sending is refused with a clear error (offline slice)");
	{
		struct ars_packet p;
		char apd[] = "ip6(saddr=2001:db8::1,daddr=2001:db8::2)+icmp6(type=128)";
		ars_init(&p);
		CHECK_EQ_INT(ars_d_build(&p, apd), -ARS_OK);
		CHECK_EQ_INT(ars_compile(&p), -ARS_OK);
		CHECK(ars_send(-1, &p, NULL, 0) != -ARS_OK);
		CHECK(p.p_error != NULL && strstr(p.p_error, "not supported yet") != NULL);
		ars_destroy(&p);
	}

	TEST("ipv6: an unknown field is an error, not silently ignored");
	{
		struct ars_packet p;
		char apd[] = "ip6(bogus=1)";
		ars_init(&p);
		CHECK(ars_d_build(&p, apd) != -ARS_OK);
		ars_destroy(&p);
		ars_init(&p);
		{
			char apd2[] = "ip6()+icmp6(bogus=1)";
			CHECK(ars_d_build(&p, apd2) != -ARS_OK);
		}
		ars_destroy(&p);
	}

	TEST("ipv6: explicit plen/nh are kept (deliberately wrong packets)");
	pkt = build_apd("ip6(saddr=2001:db8::1,daddr=2001:db8::2,plen=999,nh=99)"
			"+icmp6(type=128,cksum=0x1111)", &size);
	CHECK(pkt != NULL);
	if (pkt) {
		CHECK_EQ_INT((pkt[4] << 8) | pkt[5], 999);
		CHECK_EQ_INT(pkt[6], 99);
		CHECK_EQ_INT(pkt[42], 0x11);
		CHECK_EQ_INT(pkt[43], 0x11);
		free(pkt);
	}
}

int main(void)
{
	hping_config_init(&cfg);
	hping_context_init(&ctx);
	hping_stats_init(&stats);
	test_memstr();
	test_hex();
	test_hstring();
	test_adbuf();
	test_cksum();
	test_rand_dest();
	test_apd_build_vectors();
	test_split_roundtrip();
	test_split_malformed();
	test_display_ipopt();
	test_send_icmp_other();
	test_pcap_recv();
	test_ipv6_vectors();
	return tu_report("test_core");
}
