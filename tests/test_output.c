/* test_output.c -- the NDJSON serializer (output.c) on a captured stream.
 *
 * Unit-level: no packets, no loop; the typed setters must produce valid,
 * correctly escaped JSON, unknown values must be null (not 0). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hping2.h"
#include "globals.h"
#include "output.h"
#include "testutil.h"

/* run 'body' with the output stream captured into 'buf' */
#define CAPTURE(buf, body) do { \
	FILE *_f = tmpfile(); size_t _n; \
	output_set_stream(_f); \
	body; \
	fflush(_f); rewind(_f); \
	_n = fread(buf, 1, sizeof(buf) - 1, _f); \
	buf[_n] = '\0'; fclose(_f); \
	output_set_stream(NULL); \
} while (0)

static void test_serializer(void)
{
	char buf[1024];

	TEST("output: a full object with the schema, type and a timestamp");
	cfg.opt_json = 1;
	CAPTURE(buf, {
		out_begin("reply");
		out_str("proto", "tcp");
		out_int("ttl", 64);
		out_double("rtt_ms", 1.25);
		out_bool("dup", 0);
		out_end();
	});
	CHECK(strstr(buf, "\"schema\":1") != NULL);
	CHECK(strstr(buf, "\"type\":\"reply\"") != NULL);
	CHECK(strstr(buf, "\"ts\":") != NULL);
	CHECK(strstr(buf, "\"proto\":\"tcp\"") != NULL);
	CHECK(strstr(buf, "\"ttl\":64") != NULL);
	CHECK(strstr(buf, "\"rtt_ms\":1.2") != NULL); /* one decimal */
	CHECK(strstr(buf, "\"dup\":false") != NULL);
	CHECK(buf[0] == '{');
	CHECK(strchr(buf, '\n') == buf + strlen(buf) - 1); /* one line */
	CHECK(strstr(buf, "}\n") != NULL);

	TEST("output: null is emitted, not a zero");
	CAPTURE(buf, { out_begin("reply"); out_null("rtt_ms"); out_end(); });
	CHECK(strstr(buf, "\"rtt_ms\":null") != NULL);
	CHECK(strstr(buf, "\"rtt_ms\":0") == NULL);

	TEST("output: string escaping (quote, backslash, control)");
	CAPTURE(buf, { out_begin("x"); out_str("k", "a\"b\\c\td\ne"); out_end(); });
	CHECK(strstr(buf, "\"k\":\"a\\\"b\\\\c\\td\\ne\"") != NULL);

	TEST("output: an IPv4 address field");
	CAPTURE(buf, {
		struct in_addr a; a.s_addr = htonl(0x0a000001);
		out_begin("x"); out_ipv4("ip", a.s_addr); out_end();
	});
	CHECK(strstr(buf, "\"ip\":\"10.0.0.1\"") != NULL);

	TEST("output: unsigned 64-bit counters do not wrap");
	CAPTURE(buf, { out_begin("statistics"); out_uint("sent", 5000000000ULL); out_end(); });
	CHECK(strstr(buf, "\"sent\":5000000000") != NULL);

	TEST("output: commas separate fields, none is trailing");
	CAPTURE(buf, { out_begin("x"); out_int("a", 1); out_int("b", 2); out_end(); });
	CHECK(strstr(buf, ",\"a\":1,\"b\":2}") != NULL);

	cfg.opt_json = 0;
	CHECK_EQ_INT(output_json_enabled(), 0);
	cfg.opt_json = 1;
	CHECK_EQ_INT(output_json_enabled(), 1);
}

int main(void)
{
	hping_config_init(&cfg);
	hping_context_init(&ctx);
	hping_stats_init(&stats);
	test_serializer();
	return tu_report("test_output");
}
