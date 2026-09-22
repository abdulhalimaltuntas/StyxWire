/* test_parse.c -- parse_options() as a function: argv in, cfg out, no
 * exit(), no side effect on the network.
 *
 * Complements tests/cli.sh (which drives the real binary): here the
 * resulting configuration is inspected field by field. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>

#include "hping2.h"
#include "globals.h"
#include "testutil.h"

/* parse a command line given as separate words; output goes to /dev/null */
static int parse(const char *first, ...)
{
	char *argv[32];
	int argc = 0, rc, out = dup(1), err = dup(2), null;
	va_list ap;
	const char *a;

	argv[argc++] = "hping3";
	va_start(ap, first);
	for (a = first; a != NULL; a = va_arg(ap, const char*))
		argv[argc++] = (char*) a;
	va_end(ap);
	argv[argc] = NULL;

	hping_config_init(&cfg);
	null = open("/dev/null", O_WRONLY);
	fflush(stdout); fflush(stderr);
	dup2(null, 1); dup2(null, 2);
	rc = parse_options(argc, argv);
	fflush(stdout); fflush(stderr);
	dup2(out, 1); dup2(err, 2);
	close(out); close(err); close(null);
	return rc;
}

static void test_basic(void)
{
	TEST("parse: defaults and a typical SYN probe");
	CHECK_EQ_INT(parse("-S", "-p", "80", "-c", "3", "-i", "u1000", "10.0.0.1", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(cfg.tcp_th_flags, TH_SYN);
	CHECK_EQ_INT(cfg.dst_port, 80);
	CHECK_EQ_INT(cfg.base_dst_port, 80);
	CHECK_EQ_INT(cfg.count, 3);
	CHECK_EQ_INT(cfg.opt_waitinusec, TRUE);
	CHECK_EQ_INT(cfg.usec_delay.it_interval.tv_usec, 1000);
	CHECK_EQ_INT(hping_send_interval_us(), 1000);
	CHECK_EQ_STR(cfg.targetname, "10.0.0.1");
	CHECK_EQ_INT(cfg.src_ttl, DEFAULT_TTL);
	CHECK_EQ_INT(cfg.src_winsize, DEFAULT_SRCWINSIZE);
	CHECK_EQ_INT(cfg.initsport, -1);
	CHECK(cfg.apd_send == NULL);

	TEST("parse: state does not leak between calls");
	CHECK_EQ_INT(parse("-A", "10.0.0.2", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(cfg.tcp_th_flags, TH_ACK);	/* no SYN from the previous call */
	CHECK_EQ_INT(cfg.count, -1);
	CHECK_EQ_INT(cfg.opt_waitinusec, FALSE);
	CHECK_EQ_INT(hping_send_interval_us(), 1000000);

	TEST("parse: --fast / --faster");
	CHECK_EQ_INT(parse("--fast", "10.0.0.1", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(hping_send_interval_us(), 100000);
	CHECK_EQ_INT(parse("--faster", "10.0.0.1", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(hping_send_interval_us(), 1);
	/* Regression: --faster fell through into --tr-keep-ttl */
	CHECK_EQ_INT(cfg.opt_tr_keep_ttl, FALSE);

	TEST("parse: traceroute implies bind to ttl and ttl 1");
	CHECK_EQ_INT(parse("-T", "10.0.0.1", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(cfg.src_ttl, DEFAULT_TRACEROUTE_TTL);
	CHECK_EQ_INT(cfg.ctrlzbind, BIND_TTL);
	CHECK_EQ_INT(parse("-T", "-t", "5", "10.0.0.1", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(cfg.src_ttl, 5);

	TEST("parse: --sign sets the data size when -d is absent");
	CHECK_EQ_INT(parse("-e", "abc", "10.0.0.1", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(cfg.signlen, 3);
	CHECK_EQ_INT(cfg.data_size, 3);
	CHECK_EQ_INT(parse("-e", "abc", "-d", "2", "10.0.0.1", NULL), HPING_PARSE_ERROR);

	TEST("parse: --scan takes the port list; scan mode sends at full speed by default");
	CHECK_EQ_INT(parse("--scan", "1-10,80", "-S", "10.0.0.1", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(cfg.opt_scanmode, TRUE);
	CHECK_EQ_STR(cfg.opt_scanports, "1-10,80");
	CHECK_EQ_INT(cfg.opt_waitinusec, TRUE);
	CHECK_EQ_INT(hping_send_interval_us(), 0);
	hping_destroy(); /* frees the port list */
	CHECK_EQ_STR(cfg.opt_scanports, "");
}

static void test_help_and_errors(void)
{
	TEST("parse: help/version are DONE, not errors");
	CHECK_EQ_INT(parse("--help", NULL), HPING_PARSE_DONE);
	CHECK_EQ_INT(parse("-v", NULL), HPING_PARSE_DONE);
	CHECK_EQ_INT(parse("--icmp-help", NULL), HPING_PARSE_DONE);
	CHECK_EQ_INT(parse("--tos", "help", NULL), HPING_PARSE_DONE);

	TEST("parse: usage errors");
	CHECK_EQ_INT(parse(NULL), HPING_PARSE_ERROR);			/* no arguments */
	CHECK_EQ_INT(parse("-S", NULL), HPING_PARSE_ERROR);		/* no host */
	CHECK_EQ_INT(parse("--bogus", "10.0.0.1", NULL), HPING_PARSE_ERROR);
	CHECK_EQ_INT(parse("-c", "x", "10.0.0.1", NULL), HPING_PARSE_ERROR);
	CHECK_EQ_INT(parse("-c", "0", "10.0.0.1", NULL), HPING_PARSE_ERROR);
	CHECK_EQ_INT(parse("-t", "256", "10.0.0.1", NULL), HPING_PARSE_ERROR);
	CHECK_EQ_INT(parse("-p", "-1", "10.0.0.1", NULL), HPING_PARSE_ERROR);
	CHECK_EQ_INT(parse("10.0.0.1", "10.0.0.2", NULL), HPING_PARSE_ERROR);	/* two hosts */
	CHECK_EQ_INT(parse("-E", "/dev/null", "10.0.0.1", NULL), HPING_PARSE_ERROR);
	CHECK_EQ_INT(parse("--rand-dest", "10.0.0.x", NULL), HPING_PARSE_ERROR); /* needs -I */

	TEST("parse: unsupported ICMP types are rejected unless --force-icmp");
	CHECK_EQ_INT(parse("-1", "-C", "99", "10.0.0.1", NULL), HPING_PARSE_ERROR);
	CHECK_EQ_INT(parse("-1", "-C", "99", "--force-icmp", "10.0.0.1", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(parse("-1", "-C", "13", "10.0.0.1", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(parse("--icmp-ts", "10.0.0.1", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(cfg.opt_icmptype, 13);
	CHECK(icmp_type_supported(8) && icmp_type_supported(3) && !icmp_type_supported(42));

	TEST("parse: --rand-dest template is validated up front");
	CHECK_EQ_INT(parse("--rand-dest", "-I", "lo", "10.0.x.x", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(parse("--rand-dest", "-I", "lo", "10.0.x", NULL), HPING_PARSE_ERROR);
	CHECK_EQ_INT(parse("--rand-dest", "-I", "lo", "999.0.x.x", NULL), HPING_PARSE_ERROR);

	TEST("parse: source routes");
	CHECK_EQ_INT(parse("--lsrr", "10.0.0.1/10.0.0.2", "10.0.0.9", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(cfg.opt_lsrr, TRUE);
	CHECK_EQ_INT(cfg.lsr_length, 3 + 8);
	CHECK_EQ_INT(cfg.lsr[0], 131);		/* option type */
	CHECK_EQ_INT(cfg.lsr[1], 11);		/* length */
	CHECK_EQ_INT(cfg.lsr[2], 8);		/* default pointer */
	CHECK_EQ_INT(cfg.lsr[3], 10);
	CHECK_EQ_INT(cfg.lsr[10], 2);
	CHECK_EQ_INT(parse("--lsrr", "4:10.0.0.1", "10.0.0.9", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(cfg.lsr[2], 4);
	CHECK_EQ_INT(parse("--lsrr", "10.0.0.1/bogus", "10.0.0.9", NULL), HPING_PARSE_ERROR);
	CHECK_EQ_INT(parse("--ssrr", "300:10.0.0.1", "10.0.0.9", NULL), HPING_PARSE_ERROR);
	CHECK_EQ_INT(parse("--ssrr", "10.0.0.1;", "10.0.0.9", NULL), HPING_PARSE_ERROR);
}

static void test_apd_send(void)
{
	TEST("parse: --apd-send is stored, not executed, and needs no host");
	CHECK_EQ_INT(parse("--apd-send", "ip(daddr=10.0.0.1)+icmp()", NULL), HPING_PARSE_OK);
	CHECK_EQ_STR(cfg.apd_send, "ip(daddr=10.0.0.1)+icmp()");
	hping_destroy();
	CHECK(cfg.apd_send == NULL);
}

/* parse_route() (--lsrr/--ssrr) was previously untested; the option value
 * is "[ptr:]IP1[/IP2...]". These pin the layout it writes and, importantly,
 * the rejection of a malformed pointer prefix -- the fall-through path in
 * the ':' case that reaches the "invalid route syntax" default. */
static void test_route(void)
{
	TEST("parse: --lsrr single hop");
	CHECK_EQ_INT(parse("--lsrr", "1.2.3.4", "10.0.0.1", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(cfg.opt_lsrr, TRUE);
	CHECK_EQ_INT(cfg.lsr[0], 131);			/* LSRR option type */
	CHECK_EQ_INT(cfg.lsr_length, 7);		/* 4*1 + 3 */
	CHECK_EQ_INT(cfg.lsr[1], 7);			/* length byte */

	TEST("parse: --lsrr two hops");
	CHECK_EQ_INT(parse("--lsrr", "1.2.3.4/5.6.7.8", "10.0.0.1", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(cfg.lsr_length, 11);		/* 4*2 + 3 */

	TEST("parse: --lsrr with a pointer prefix");
	CHECK_EQ_INT(parse("--lsrr", "8:1.2.3.4", "10.0.0.1", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(cfg.lsr[2], 8);			/* the route pointer */

	TEST("parse: --ssrr single hop");
	CHECK_EQ_INT(parse("--ssrr", "1.2.3.4", "10.0.0.1", NULL), HPING_PARSE_OK);
	CHECK_EQ_INT(cfg.opt_ssrr, TRUE);
	CHECK_EQ_INT(cfg.ssr[0], 137);			/* SSRR option type */

	/* rejected: a pointer prefix >= 256 falls through to the error */
	TEST("parse: --lsrr rejects an out-of-range pointer prefix");
	CHECK_EQ_INT(parse("--lsrr", "999:1.2.3.4", "10.0.0.1", NULL), HPING_PARSE_ERROR);

	/* rejected: junk that is neither an IP nor a valid prefix */
	TEST("parse: --lsrr rejects malformed syntax");
	CHECK_EQ_INT(parse("--lsrr", "@", "10.0.0.1", NULL), HPING_PARSE_ERROR);
}

int main(void)
{
	hping_config_init(&cfg);
	hping_context_init(&ctx);
	hping_stats_init(&stats);
	test_basic();
	test_help_and_errors();
	test_apd_send();
	test_route();
	return tu_report("test_parse");
}
