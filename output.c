/* output.c -- see output.h. */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "hping2.h"
#include "globals.h"
#include "output.h"

static FILE *out_fp;		/* NULL -> stdout, resolved lazily */
static int out_need_comma;	/* a field was already written in this object */

int output_json_enabled(void)
{
	return cfg.opt_json;
}

void output_set_stream(FILE *fp)
{
	out_fp = fp;
}

void output_init(void)
{
	if (out_fp == NULL)
		out_fp = stdout;
}

static FILE *stream(void)
{
	return out_fp ? out_fp : stdout;
}

/* Write 's' as a JSON string body (without the surrounding quotes),
 * escaping what RFC 8259 requires. Non-printable bytes become \u00XX. */
static void put_escaped(FILE *fp, const char *s)
{
	const unsigned char *p = (const unsigned char *) s;

	for (; *p; p++) {
		switch (*p) {
		case '"':  fputs("\\\"", fp); break;
		case '\\': fputs("\\\\", fp); break;
		case '\b': fputs("\\b", fp); break;
		case '\f': fputs("\\f", fp); break;
		case '\n': fputs("\\n", fp); break;
		case '\r': fputs("\\r", fp); break;
		case '\t': fputs("\\t", fp); break;
		default:
			if (*p < 0x20)
				fprintf(fp, "\\u%04x", *p);
			else
				fputc(*p, fp);
		}
	}
}

static void key(const char *k)
{
	FILE *fp = stream();

	if (out_need_comma)
		fputc(',', fp);
	fputc('"', fp);
	put_escaped(fp, k);
	fputs("\":", fp);
	out_need_comma = 1;
}

void out_begin(const char *type)
{
	FILE *fp = stream();

	fputc('{', fp);
	out_need_comma = 0;
	out_int("schema", STYXWIRE_JSON_SCHEMA);
	out_str("type", type);
	/* wall-clock milliseconds since the epoch, for correlation */
	out_uint("ts", (unsigned long long) (hping_wall_us() / 1000));
}

void out_str(const char *k, const char *v)
{
	FILE *fp = stream();

	key(k);
	fputc('"', fp);
	put_escaped(fp, v);
	fputc('"', fp);
}

void out_int(const char *k, long long v)
{
	key(k);
	fprintf(stream(), "%lld", v);
}

void out_uint(const char *k, unsigned long long v)
{
	key(k);
	fprintf(stream(), "%llu", v);
}

void out_double(const char *k, double v)
{
	key(k);
	fprintf(stream(), "%.1f", v);
}

void out_bool(const char *k, int v)
{
	key(k);
	fputs(v ? "true" : "false", stream());
}

void out_null(const char *k)
{
	key(k);
	fputs("null", stream());
}

void out_ipv4(const char *k, unsigned long netaddr)
{
	struct in_addr in;

	in.s_addr = (in_addr_t) netaddr;
	out_str(k, inet_ntoa(in));
}

void out_end(void)
{
	FILE *fp = stream();

	fputc('}', fp);
	fputc('\n', fp);
	fflush(fp);
	out_need_comma = 0;
}
