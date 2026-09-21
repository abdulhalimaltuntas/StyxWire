/* bench.c -- reproducible offline benchmark for the StyxWire packet engine.
 *
 * Every workload is pure computation on in-memory buffers: no socket, no
 * capture device, no file, no clock other than the one that measures it,
 * and no randomness. Running it twice on an idle machine must give the
 * same numbers within noise, and running it as an ordinary user must be
 * enough.
 *
 * Method. Each workload is run 'iterations' times per repetition and the
 * whole thing is repeated 'repetitions' times. Reported are the minimum,
 * the median and the maximum nanoseconds per operation over the
 * repetitions: the minimum is the least noisy estimate of the cost, the
 * spread says how much the machine interfered. One untimed warm-up
 * repetition primes the caches and the allocator. Numbers are only
 * comparable against numbers taken the same way on the same machine, so
 * the header records the machine, the compiler, the flags and the exact
 * command line.
 *
 * Allocation accounting is compiled in with -DBENCH_WRAP_MALLOC plus the
 * linker's --wrap (see "make bench"); without it the allocation columns
 * read "n/a" instead of lying. realloc is counted as one allocation of
 * its new size, because the old size is not knowable here.
 *
 *   make bench                 build and run with the defaults
 *   tests/bench -n 20000 -r 7  more iterations, more repetitions
 *   tests/bench -w split       one workload
 *   tests/bench --json         one JSON object per workload
 *   tests/bench --selftest     check that every workload computes what
 *                              it claims (this is what "make check" runs)
 *
 * Copyright GPL v2. */

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE		/* sched_getaffinity, for the report header */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#ifdef __linux__
#include <sched.h>
#endif

#include "ars.h"

#define BENCH_MAXREP 64

/* ------------------------------------------------------------------ *
 * allocation accounting                                              *
 * ------------------------------------------------------------------ */

static unsigned long long alloc_calls, alloc_bytes, free_calls;

#ifdef BENCH_WRAP_MALLOC
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void __real_free(void *);

void *__wrap_malloc(size_t n)
{
	alloc_calls++; alloc_bytes += n;
	return __real_malloc(n);
}

void *__wrap_calloc(size_t n, size_t s)
{
	alloc_calls++; alloc_bytes += (unsigned long long) n * s;
	return __real_calloc(n, s);
}

void *__wrap_realloc(void *p, size_t n)
{
	/* realloc releases the old block and returns a new one: count
	 * both sides, or a growing buffer looks like a leak. The old
	 * block's size is not knowable here, so only the new size is
	 * added to the byte total. */
	if (p == NULL) {
		alloc_calls++; alloc_bytes += n;
	} else if (n == 0) {
		free_calls++;
	} else {
		alloc_calls++; alloc_bytes += n;
		free_calls++;
	}
	return __real_realloc(p, n);
}

void __wrap_free(void *p)
{
	if (p) free_calls++;
	__real_free(p);
}

static const int alloc_accounting = 1;
#else
static const int alloc_accounting = 0;
#endif

/* ------------------------------------------------------------------ *
 * workloads                                                          *
 * ------------------------------------------------------------------ */

#define APD4	"ip(saddr=10.0.0.1,daddr=10.0.0.2,ttl=64)+" \
		"tcp(sport=1234,dport=80,flags=s,seq=1,win=512)+" \
		"data(str=styxwire benchmark payload)"
#define APD6	"ip6(saddr=2001:db8::1,daddr=2001:db8::2,hlim=64)+" \
		"tcp(sport=1234,dport=80,flags=s,seq=1,win=512)+" \
		"data(str=styxwire benchmark payload)"

/* bytes of APD4 / APD6, built once at start-up */
static unsigned char *wire4, *wire6;
static size_t wire4_len, wire6_len;
static char describe_buf[8192];

/* Build 'apd' into freshly allocated wire bytes. Returns 0 on success. */
static int build_once(const char *apd, unsigned char **pkt, size_t *len)
{
	struct ars_packet p;
	char text[512];
	int r;

	strlcpy(text, apd, sizeof(text));
	ars_init(&p);
	r = ars_d_build(&p, text);
	if (r == -ARS_OK)
		r = ars_compile(&p);
	if (r == -ARS_OK)
		r = ars_build_packet(&p, pkt, len);
	ars_destroy(&p);
	return r == -ARS_OK ? 0 : -1;
}

/* Each workload returns a value derived from its result so the compiler
 * cannot optimise the call away, and so --selftest can check it. */

static unsigned long w_build4(void)
{
	unsigned char *pkt; size_t len;

	if (build_once(APD4, &pkt, &len) < 0) return 0;
	free(pkt);
	return (unsigned long) len;
}

static unsigned long w_build6(void)
{
	unsigned char *pkt; size_t len;

	if (build_once(APD6, &pkt, &len) < 0) return 0;
	free(pkt);
	return (unsigned long) len;
}

static unsigned long w_split4(void)
{
	struct ars_packet p;
	unsigned long n;

	ars_init(&p);
	if (ars_split_packet(wire4, wire4_len, 0, &p) != -ARS_OK) n = 0;
	else n = (unsigned long) p.p_layer_nr;
	ars_destroy(&p);
	return n;
}

static unsigned long w_split6(void)
{
	struct ars_packet p;
	unsigned long n;

	ars_init(&p);
	if (ars_split_packet(wire6, wire6_len, 0, &p) != -ARS_OK) n = 0;
	else n = (unsigned long) p.p_layer_nr;
	ars_destroy(&p);
	return n;
}

static unsigned long w_describe4(void)
{
	struct ars_packet p;
	unsigned long n = 0;

	ars_init(&p);
	if (ars_split_packet(wire4, wire4_len, 0, &p) == -ARS_OK &&
	    ars_d_from_ars(describe_buf, sizeof(describe_buf), &p) == -ARS_OK)
		n = (unsigned long) strlen(describe_buf);
	ars_destroy(&p);
	return n;
}

static unsigned long w_cksum(void)
{
	static unsigned char buf[1500];

	if (buf[0] == 0)
		for (size_t i = 0; i < sizeof(buf); i++)
			buf[i] = (unsigned char) (i * 7 + 1);
	return ars_cksum(buf, sizeof(buf));
}

struct workload {
	const char *name;
	const char *what;		/* one line, for the report */
	unsigned long (*run)(void);
	unsigned long expect;		/* --selftest: 0 = "just non-zero" */
};

static struct workload workloads[] = {
    { "build4",   "APD text -> IPv4/TCP/data wire bytes (parse, compile, serialise)", w_build4,    66 },
    { "build6",   "APD text -> IPv6/TCP/data wire bytes",                             w_build6,    86 },
    { "split4",   "IPv4/TCP/data wire bytes -> layers (dissect)",                     w_split4,     3 },
    { "split6",   "IPv6/TCP/data wire bytes -> layers",                               w_split6,     3 },
    { "describe4","IPv4 wire bytes -> layers -> APD text",                            w_describe4,  0 },
    { "cksum",    "Internet checksum over 1500 bytes",                                w_cksum,      0 },
};
#define NWORKLOADS ((int) (sizeof(workloads)/sizeof(workloads[0])))

/* ------------------------------------------------------------------ *
 * harness                                                            *
 * ------------------------------------------------------------------ */

static long long mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long) ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int cmp_double(const void *a, const void *b)
{
	double x = *(const double*)a, y = *(const double*)b;

	return x < y ? -1 : (x > y ? 1 : 0);
}

static volatile unsigned long sink;

struct result {
	double min, med, max;		/* nanoseconds per operation */
	double alloc_per_op, bytes_per_op;
	int leaked;			/* allocations not matched by frees:
					 * a smoke signal, not LeakSanitizer */
};

static void run_workload(struct workload *w, int iterations, int repetitions,
			 struct result *r)
{
	double ns[BENCH_MAXREP];
	unsigned long long a0, b0, f0;
	int i, k;

	/* untimed warm-up */
	for (i = 0; i < iterations; i++)
		sink = w->run();

	a0 = alloc_calls; b0 = alloc_bytes; f0 = free_calls;
	for (k = 0; k < repetitions; k++) {
		long long t0 = mono_ns(), t1;

		for (i = 0; i < iterations; i++)
			sink = w->run();
		t1 = mono_ns();
		ns[k] = (double) (t1 - t0) / iterations;
	}
	r->alloc_per_op = (double) (alloc_calls - a0) /
			  ((double) iterations * repetitions);
	r->bytes_per_op = (double) (alloc_bytes - b0) /
			  ((double) iterations * repetitions);
	r->leaked = (alloc_calls - a0) != (free_calls - f0);

	qsort(ns, (size_t) repetitions, sizeof(ns[0]), cmp_double);
	r->min = ns[0];
	r->med = ns[repetitions / 2];
	r->max = ns[repetitions - 1];
}

/* first "model name" line of /proc/cpuinfo, or NULL */
static const char *cpu_model(void)
{
	static char buf[128];
	char line[256];
	FILE *fp = fopen("/proc/cpuinfo", "r");

	if (fp == NULL)
		return NULL;
	while (fgets(line, sizeof(line), fp)) {
		char *c;

		if (strncmp(line, "model name", 10) != 0)
			continue;
		c = strchr(line, ':');
		if (c == NULL) break;
		c++;
		while (*c == ' ') c++;
		strlcpy(buf, c, sizeof(buf));
		c = strchr(buf, '\n');
		if (c) *c = '\0';
		fclose(fp);
		return buf;
	}
	fclose(fp);
	return NULL;
}

static void print_header(int argc, char **argv, int iterations, int repetitions)
{
	struct utsname u;
	const char *cpu = cpu_model();
	int i;

	printf("StyxWire offline benchmark\n");
	printf("--------------------------\n");
	printf("command    :");
	for (i = 0; i < argc; i++) printf(" %s", argv[i]);
	printf("\n");
	if (uname(&u) == 0)
		printf("system     : %s %s %s\n", u.sysname, u.release, u.machine);
	if (cpu)
		printf("cpu        : %s\n", cpu);
	printf("compiler   : %s\n", BENCH_CC);
	printf("cflags     : %s\n", BENCH_CFLAGS);
	printf("workload   : %d iterations x %d repetitions (+1 warm-up)\n",
		iterations, repetitions);
#ifdef __linux__
	{
		cpu_set_t set;

		if (sched_getaffinity(0, sizeof(set), &set) == 0) {
			int c, first = 1;

			printf("affinity   :");
			for (c = 0; c < CPU_SETSIZE; c++)
				if (CPU_ISSET(c, &set)) {
					printf("%s%d", first ? " cpu " : ",", c);
					first = 0;
				}
			printf("%s\n", CPU_COUNT(&set) > 1 ?
				"  (not pinned: expect run-to-run spread on a "
				"machine with unequal cores)" : "");
		}
	}
#endif
	printf("allocations: %s\n", alloc_accounting ?
		"counted (linker --wrap)" :
		"not counted (rebuild with BENCH_WRAP=... for the columns)");
	printf("\n");
	printf("%-10s %10s %10s %10s %12s %8s %9s\n",
		"workload", "ns/op", "median", "max", "op/s", "allocs", "bytes");
	printf("%-10s %10s %10s %10s %12s %8s %9s\n",
		"--------", "-----", "------", "---", "----", "------", "-----");
}

static void print_row(const struct workload *w, const struct result *r)
{
	char allocs[16], bytes[16];

	if (alloc_accounting) {
		snprintf(allocs, sizeof(allocs), "%.2f", r->alloc_per_op);
		snprintf(bytes, sizeof(bytes), "%.1f", r->bytes_per_op);
	} else {
		strlcpy(allocs, "n/a", sizeof(allocs));
		strlcpy(bytes, "n/a", sizeof(bytes));
	}
	printf("%-10s %10.1f %10.1f %10.1f %12.0f %8s %9s%s\n",
		w->name, r->min, r->med, r->max,
		r->min > 0 ? 1e9 / r->min : 0, allocs, bytes,
		r->leaked ? "  LEAK" : "");
}

static void print_json(const struct workload *w, const struct result *r,
		       int iterations, int repetitions)
{
	printf("{\"workload\":\"%s\",\"iterations\":%d,\"repetitions\":%d,"
	       "\"ns_per_op_min\":%.1f,\"ns_per_op_median\":%.1f,"
	       "\"ns_per_op_max\":%.1f,\"ops_per_sec\":%.0f,",
		w->name, iterations, repetitions, r->min, r->med, r->max,
		r->min > 0 ? 1e9 / r->min : 0);
	if (alloc_accounting)
		printf("\"allocs_per_op\":%.3f,\"alloc_bytes_per_op\":%.1f,"
		       "\"balanced\":%s}\n",
			r->alloc_per_op, r->bytes_per_op,
			r->leaked ? "false" : "true");
	else
		printf("\"allocs_per_op\":null,\"alloc_bytes_per_op\":null,"
		       "\"balanced\":null}\n");
}

static int selftest(void)
{
	int i, bad = 0;

	for (i = 0; i < NWORKLOADS; i++) {
		unsigned long v = workloads[i].run();

		if (v == 0 || (workloads[i].expect && v != workloads[i].expect)) {
			fprintf(stderr, "bench: workload %s returned %lu, "
				"expected %s%lu\n", workloads[i].name, v,
				workloads[i].expect ? "" : "non-zero ",
				workloads[i].expect);
			bad++;
		}
	}
	/* the two wire buffers must round trip through the dissector */
	if (w_split4() != 3 || w_split6() != 3) {
		fprintf(stderr, "bench: wire fixtures do not dissect\n");
		bad++;
	}
	if (bad == 0)
		printf("bench: %d workloads self-tested OK\n", NWORKLOADS);
	return bad == 0 ? 0 : 1;
}

static void usage(void)
{
	printf("usage: bench [-n iterations] [-r repetitions] [-w workload] "
	       "[--json] [--list] [--selftest]\n");
}

int main(int argc, char **argv)
{
	int iterations = 20000, repetitions = 5;
	int json = 0, i;
	const char *only = NULL;
	struct rusage ru;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-n") && i+1 < argc)
			iterations = atoi(argv[++i]);
		else if (!strcmp(argv[i], "-r") && i+1 < argc)
			repetitions = atoi(argv[++i]);
		else if (!strcmp(argv[i], "-w") && i+1 < argc)
			only = argv[++i];
		else if (!strcmp(argv[i], "--json"))
			json = 1;
		else if (!strcmp(argv[i], "--list")) {
			for (i = 0; i < NWORKLOADS; i++)
				printf("%-10s %s\n", workloads[i].name,
					workloads[i].what);
			return 0;
		} else if (!strcmp(argv[i], "--selftest")) {
			if (build_once(APD4, &wire4, &wire4_len) < 0 ||
			    build_once(APD6, &wire6, &wire6_len) < 0) {
				fprintf(stderr, "bench: cannot build the fixtures\n");
				return 1;
			}
			return selftest();
		} else {
			usage();
			return !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") ? 0 : 1;
		}
	}
	if (iterations < 1 || repetitions < 1 || repetitions > BENCH_MAXREP) {
		fprintf(stderr, "bench: iterations >= 1 and "
			"1 <= repetitions <= %d\n", BENCH_MAXREP);
		return 1;
	}
	if (build_once(APD4, &wire4, &wire4_len) < 0 ||
	    build_once(APD6, &wire6, &wire6_len) < 0) {
		fprintf(stderr, "bench: cannot build the fixtures\n");
		return 1;
	}
	if (!json)
		print_header(argc, argv, iterations, repetitions);
	for (i = 0; i < NWORKLOADS; i++) {
		struct result r;

		if (only && strcmp(only, workloads[i].name))
			continue;
		run_workload(&workloads[i], iterations, repetitions, &r);
		if (json)
			print_json(&workloads[i], &r, iterations, repetitions);
		else
			print_row(&workloads[i], &r);
	}
	if (!json && getrusage(RUSAGE_SELF, &ru) == 0) {
		printf("\npeak resident set: %ld KiB (ru_maxrss; KiB on Linux, "
			"bytes on some BSDs)\n", ru.ru_maxrss);
		printf("wire fixtures: IPv4 %zu bytes, IPv6 %zu bytes\n",
			wire4_len, wire6_len);
	}
	free(wire4);
	free(wire6);
	return 0;
}
