/* clock.c -- time and randomness sources of hping3.
 *
 * All elapsed time computations (round trip times, sending intervals,
 * deadlines, timeouts) use one monotonic clock, hping_monotonic_us().
 * The wall clock, hping_wall_us(), is only used where the protocol or the
 * output needs calendar time (the ICMP timestamp option carries
 * milliseconds since midnight UT).
 *
 * Both clocks and the random source are function pointers in the context
 * (see globals.h), so that tests can replace them with deterministic
 * implementations: hping_clock_set() / hping_random_set().
 *
 * Copyright (C) 1999 by Salvatore Sanfilippo (historical getusec.c),
 * GPL version 2. */

#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include "hping2.h"
#include "globals.h"

static long long system_monotonic_us(void *arg)
{
#if defined(CLOCK_MONOTONIC)
	struct timespec ts;

	(void) arg;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
		return (long long) ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
#endif
	{
		/* fallback: not monotonic, but the best available */
		struct timeval tv;
		(void) arg;
		gettimeofday(&tv, NULL);
		return (long long) tv.tv_sec * 1000000LL + tv.tv_usec;
	}
}

static long long system_wall_us(void *arg)
{
	struct timeval tv;

	(void) arg;
	gettimeofday(&tv, NULL);
	return (long long) tv.tv_sec * 1000000LL + tv.tv_usec;
}

static unsigned int system_random_u32(void *arg)
{
	(void) arg;
	return hp_rand();
}

/* Install the system clocks and random source (called by
 * hping_context_init()). */
void hping_clock_system(struct hping_context *x)
{
	x->clock.monotonic_us = system_monotonic_us;
	x->clock.wall_us = system_wall_us;
	x->clock.arg = NULL;
	x->random.u32 = system_random_u32;
	x->random.arg = NULL;
}

void hping_clock_set(long long (*monotonic_us)(void*),
		     long long (*wall_us)(void*), void *arg)
{
	if (monotonic_us)
		ctx.clock.monotonic_us = monotonic_us;
	if (wall_us)
		ctx.clock.wall_us = wall_us;
	ctx.clock.arg = arg;
}

void hping_random_set(unsigned int (*u32)(void*), void *arg)
{
	ctx.random.u32 = u32;
	ctx.random.arg = arg;
}

/* A context that was never initialised gets the system sources: the Tcl
 * entry point and the tests must not depend on the init order. */
static void ensure_sources(void)
{
	if (ctx.clock.monotonic_us == NULL || ctx.clock.wall_us == NULL ||
	    ctx.random.u32 == NULL)
		hping_clock_system(&ctx);
}

long long hping_monotonic_us(void)
{
	ensure_sources();
	return ctx.clock.monotonic_us(ctx.clock.arg);
}

long long hping_wall_us(void)
{
	ensure_sources();
	return ctx.clock.wall_us(ctx.clock.arg);
}

unsigned int hping_rand(void)
{
	ensure_sources();
	return ctx.random.u32(ctx.random.arg);
}

/* Milliseconds since midnight UT, as carried by the ICMP timestamp
 * messages (RFC 792). Wall clock by definition. */
time_t milliseconds(void)
{
	long long us = hping_wall_us();
	return (time_t) (((us / 1000000LL) % 86400) * 1000 + (us % 1000000LL) / 1000);
}

/* Milliseconds on the monotonic clock: for elapsed time measurements
 * (TCP timestamp HZ estimation, clock skew sampling). Historically this
 * was wall clock milliseconds since the epoch; only differences of its
 * values are ever used, which is what a monotonic clock is for. */
long long mstime(void)
{
	return hping_monotonic_us() / 1000;
}
