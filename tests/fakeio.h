/* fakeio.h -- fake clock and scripted capture input for loop tests.
 *
 * Included by tests that drive lifecycle.c / scan.c offline: the clock
 * only advances when the loop waits, frames arrive at scripted times, a
 * "signal" can be simulated after a number of waits. Everything is
 * static, one instance per test binary. */

#ifndef HPING_FAKEIO_H
#define HPING_FAKEIO_H

#include <string.h>
#include "hping2.h"
#include "globals.h"
#include "testutil.h"

#define FAKE_LOCAL  0xc0a80107UL	/* 192.168.1.7 */
#define FAKE_REMOTE 0xc0a80106UL	/* 192.168.1.6 */

/* ------------------------------------------------------------------ */
/* fake clock                                                          */
/* ------------------------------------------------------------------ */

static long long fake_now_us;		/* monotonic */
static long long fake_wall_offset_us;	/* wall = mono + offset (jumps!) */

static long long fake_mono(void *arg) { (void) arg; return fake_now_us; }
static long long fake_wall(void *arg) { (void) arg; return fake_now_us + fake_wall_offset_us; }

/* ------------------------------------------------------------------ */
/* scripted frames                                                     */
/* ------------------------------------------------------------------ */

struct scripted {
	long long at_us;	/* arrival time on the fake clock */
	unsigned char data[128];
	int len;
	int delivered;
};

static struct scripted frames[32];
static int nframes;
static int stop_after_waits;	/* simulate SIGINT after that many waits */
static int waits;

static void script_reset(void)
{
	memset(frames, 0, sizeof(frames));
	nframes = 0;
	stop_after_waits = 0;
	waits = 0;
}

/* a TCP reply from FAKE_REMOTE:dport to FAKE_LOCAL:sport, arriving at 'at_us' */
static void script_reply_from(long long at_us, int dport, int sport, int flags)
{
	struct scripted *f = &frames[nframes++];
	unsigned short ck;
	int hlen;

	f->at_us = at_us;
	hlen = tu_build_ip(f->data, 0, 40, 6, FAKE_REMOTE, FAKE_LOCAL);
	tu_build_tcp(f->data + hlen, dport, sport, flags, 5);
	ck = tu_l4_cksum(FAKE_REMOTE, FAKE_LOCAL, 6, f->data + hlen, 20);
	memcpy(f->data + hlen + 16, &ck, 2);
	f->len = hlen + 20;
}

static struct scripted *next_pending(void)
{
	struct scripted *best = NULL;
	int i;

	for (i = 0; i < nframes; i++) {
		if (frames[i].delivered)
			continue;
		if (best == NULL || frames[i].at_us < best->at_us)
			best = &frames[i];
	}
	return best;
}

/* The loop asks to wait up to timeout_us: advance the clock to the
 * earliest of the timeout and the next scripted arrival. */
static int fake_wait(long long timeout_us)
{
	struct scripted *f = next_pending();
	long long deadline;

	waits++;
	if (stop_after_waits && waits >= stop_after_waits) {
		hping_stop(HPING_STOP_SIGNAL); /* what the SIGINT handler causes */
		return 0;
	}
	if (timeout_us < 0) {
		if (f == NULL) {
			/* nothing will ever arrive: a real run would block
			 * until a signal; report it as an error to end the
			 * test instead of hanging */
			return -1;
		}
		if (f->at_us > fake_now_us)
			fake_now_us = f->at_us;
		return 1;
	}
	deadline = fake_now_us + timeout_us;
	if (f != NULL && f->at_us <= deadline) {
		if (f->at_us > fake_now_us)
			fake_now_us = f->at_us;
		return 1;
	}
	fake_now_us = deadline;
	return 0;
}

static int fake_read(char *buf, int size)
{
	struct scripted *f = next_pending();

	if (f == NULL || f->at_us > fake_now_us)
		return 0;
	f->delivered = 1;
	if (f->len > size)
		return -1;
	memcpy(buf, f->data, f->len);
	return f->len;
}


/* install the fake clock and I/O in a freshly initialised context */
static void fakeio_install(long long start_us)
{
	fake_now_us = start_us;
	fake_wall_offset_us = 1700000000LL * 1000000LL;
	hping_clock_set(fake_mono, fake_wall, NULL);
	ctx.io.wait = fake_wait;
	ctx.io.read = fake_read;
	script_reset();
}

#endif /* HPING_FAKEIO_H */
