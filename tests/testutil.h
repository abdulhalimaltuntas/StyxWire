/* testutil.h -- tiny assertion helpers for the hping3 offline test-suite.
 *
 * No framework: every test binary is a plain C program that links the
 * real hping objects, calls the functions under test with crafted input
 * and reports PASS/FAIL. Nothing here opens sockets or capture devices.
 *
 * Copyright (C) 2026, GPL version 2 like the rest of hping3. */

#ifndef HPING_TESTUTIL_H
#define HPING_TESTUTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tu_failures = 0;
static int tu_checks = 0;
static const char *tu_current = "";

#define TEST(name) do { tu_current = (name); } while (0)

#define CHECK(cond) do { \
	tu_checks++; \
	if (!(cond)) { \
		tu_failures++; \
		fprintf(stderr, "FAIL %s:%d [%s]: %s\n", __FILE__, __LINE__, \
			tu_current, #cond); \
	} \
} while (0)

#define CHECK_EQ_INT(a, b) do { \
	long long _a = (long long)(a), _b = (long long)(b); \
	tu_checks++; \
	if (_a != _b) { \
		tu_failures++; \
		fprintf(stderr, "FAIL %s:%d [%s]: %s == %s (%lld != %lld)\n", \
			__FILE__, __LINE__, tu_current, #a, #b, _a, _b); \
	} \
} while (0)

#define CHECK_EQ_STR(a, b) do { \
	const char *_a = (a), *_b = (b); \
	tu_checks++; \
	if (_a == NULL || _b == NULL || strcmp(_a, _b) != 0) { \
		tu_failures++; \
		fprintf(stderr, "FAIL %s:%d [%s]: %s == %s\n  got:  \"%s\"\n  want: \"%s\"\n", \
			__FILE__, __LINE__, tu_current, #a, #b, \
			_a ? _a : "(null)", _b ? _b : "(null)"); \
	} \
} while (0)

#define CHECK_MEM_EQ(a, b, n) do { \
	tu_checks++; \
	if (memcmp((a), (b), (n)) != 0) { \
		tu_failures++; \
		fprintf(stderr, "FAIL %s:%d [%s]: memcmp(%s, %s, %s)\n", \
			__FILE__, __LINE__, tu_current, #a, #b, #n); \
	} \
} while (0)

static int tu_report(const char *binary)
{
	if (tu_failures) {
		fprintf(stderr, "%s: %d of %d checks FAILED\n", binary,
			tu_failures, tu_checks);
		return 1;
	}
	printf("%s: %d checks passed\n", binary, tu_checks);
	return 0;
}

/* ---- packet building helpers (host byte order in, wire bytes out) ---- */

static void tu_put16(unsigned char *, unsigned int) __attribute__((unused));
static void tu_put16(unsigned char *p, unsigned int v)
{
	p[0] = (v >> 8) & 0xff;
	p[1] = v & 0xff;
}

static void tu_put32(unsigned char *, unsigned long) __attribute__((unused));
static void tu_put32(unsigned char *p, unsigned long v)
{
	p[0] = (v >> 24) & 0xff;
	p[1] = (v >> 16) & 0xff;
	p[2] = (v >> 8) & 0xff;
	p[3] = v & 0xff;
}

/* RFC 1071 checksum over 'len' bytes, returned in network byte order
 * ready to be stored with memcpy(). Independent from the hping code. */
static unsigned short tu_cksum(const unsigned char *, int) __attribute__((unused));
static unsigned short tu_cksum(const unsigned char *buf, int len)
{
	unsigned long sum = 0;
	int i;

	for (i = 0; i + 1 < len; i += 2)
		sum += (buf[i] << 8) | buf[i+1];
	if (i < len)
		sum += buf[i] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	sum = ~sum & 0xffff;
	/* store big endian */
	return (unsigned short) (((sum & 0xff) << 8) | (sum >> 8));
}

/* Build an IPv4 header (20 bytes + options) at 'p'. 'optlen' must be a
 * multiple of 4 and the option bytes must already be at p+20.
 * Returns the header length. */
static int tu_build_ip(unsigned char *, int, int, int, unsigned long, unsigned long) __attribute__((unused));
static int tu_build_ip(unsigned char *p, int optlen, int tot_len,
		       int proto, unsigned long saddr, unsigned long daddr)
{
	int hlen = 20 + optlen;
	unsigned short ck;

	memset(p, 0, 20);
	p[0] = 0x40 | (hlen / 4);
	tu_put16(p+2, tot_len);
	tu_put16(p+4, 0x1234);
	p[8] = 64;
	p[9] = proto;
	tu_put32(p+12, saddr);
	tu_put32(p+16, daddr);
	ck = tu_cksum(p, hlen);
	memcpy(p+10, &ck, 2);
	return hlen;
}

/* Build a TCP header without options at 'p' (20 bytes), checksum 0. */
static int tu_build_tcp(unsigned char *, int, int, int, int) __attribute__((unused));
static int tu_build_tcp(unsigned char *p, int sport, int dport, int flags,
			int doff_words)
{
	memset(p, 0, 20);
	tu_put16(p, sport);
	tu_put16(p+2, dport);
	tu_put32(p+4, 1000);
	tu_put32(p+8, 2000);
	p[12] = (doff_words & 0xf) << 4;
	p[13] = flags;
	tu_put16(p+14, 512);
	return 20;
}

/* TCP/UDP checksum with the IPv4 pseudo header. 'seg' is the transport
 * segment of 'len' bytes, whose checksum field must be zero. */
static unsigned short tu_l4_cksum(unsigned long, unsigned long, int, const unsigned char *, int) __attribute__((unused));
static unsigned short tu_l4_cksum(unsigned long saddr, unsigned long daddr,
				  int proto, const unsigned char *seg, int len)
{
	unsigned char *buf = malloc(12 + len);
	unsigned short ck;

	tu_put32(buf, saddr);
	tu_put32(buf+4, daddr);
	buf[8] = 0;
	buf[9] = proto;
	tu_put16(buf+10, len);
	memcpy(buf+12, seg, len);
	ck = tu_cksum(buf, 12 + len);
	free(buf);
	return ck;
}

#endif /* HPING_TESTUTIL_H */
