/* output.h -- structured (NDJSON) output for StyxWire.
 *
 * With --json the reply, ICMP-error and statistics events are written to
 * stdout as one JSON object per line (NDJSON); diagnostics and the banner
 * go to stderr. Without --json nothing here changes the historical
 * human-readable output, which the call sites still produce themselves.
 *
 * A value that is not known is emitted as JSON null, never as a
 * misleading zero (for example rtt_ms when the reply matched no probe).
 *
 * Copyright (C) 2026, GPL version 2. */

#ifndef HPING_OUTPUT_H
#define HPING_OUTPUT_H

#include <stdio.h>

#define STYXWIRE_JSON_SCHEMA 1

/* Non-zero when --json is active (set by output_init from cfg). */
int output_json_enabled(void);

/* Where structured events go (stdout). Tests can redirect it. */
void output_set_stream(FILE *fp);
void output_init(void);

/* One NDJSON object. begin() opens it with the schema, the event type and
 * a wall-clock timestamp; the typed setters append "key":value; end()
 * closes the object with a newline and flushes. Between begin and end the
 * module holds the stream, so a full event must be built before the next
 * begin. */
void out_begin(const char *type);
void out_str(const char *key, const char *val);
void out_int(const char *key, long long val);
void out_uint(const char *key, unsigned long long val);
void out_double(const char *key, double val);	/* one decimal, like the ms output */
void out_bool(const char *key, int val);
void out_null(const char *key);
void out_ipv4(const char *key, unsigned long netaddr); /* in_addr.s_addr order */
void out_end(void);

#endif /* HPING_OUTPUT_H */
