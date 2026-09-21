/* test_loop.c -- the event loop (lifecycle.c) with a fake clock and
 * scripted input.
 *
 * ctx.clock is replaced by a clock that only moves when the loop waits,
 * ctx.io by a wait/read pair that delivers frames at scripted times and
 * send_ip_handler() by the recording stub. So a whole session (probes at
 * their deadlines, replies with known delays, the late reply timeout, a
 * user interrupt) runs in a few microseconds of real time and is exactly
 * reproducible: sending times, RTTs and counters are checked to the
 * microsecond.
 *
 * No socket is opened: hping_init() is not used, the fields it would fill
 * are set here. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "hping2.h"
#include "globals.h"
#include "stub_send.h"
#include "testutil.h"
#include "fakeio.h"

#define LOCAL  FAKE_LOCAL
#define REMOTE FAKE_REMOTE
#define SPORT  4321
#define DPORT  80

static void script_reply(long long at_us, int sport, int flags)
{
	script_reply_from(at_us, DPORT, sport, flags);
}

/* ------------------------------------------------------------------ */
/* session setup                                                       */
/* ------------------------------------------------------------------ */

static void session_reset(long long interval_us, int count)
{
	hping_config_init(&cfg);
	hping_context_init(&ctx);
	hping_stats_init(&stats);
	stub_send_reset();
	fakeio_install(1000000); /* not zero: catches "uninitialised = 0" bugs */

	strcpy(cfg.targetname, "192.168.1.6");
	strcpy(cfg.ifname, "fake0");
	strcpy(ctx.targetstraddr, "192.168.1.6");
	ctx.local.sin_addr.s_addr = htonl(LOCAL);
	ctx.remote.sin_addr.s_addr = htonl(REMOTE);
	ctx.linkhdr_size = 0;
	cfg.initsport = SPORT;
	ctx.src_port = SPORT;
	cfg.base_dst_port = cfg.dst_port = DPORT;
	cfg.tcp_th_flags = TH_SYN;
	cfg.count = count;
	cfg.opt_quiet = TRUE;
	if (interval_us >= 0) {
		cfg.opt_waitinusec = TRUE;
		cfg.usec_delay.it_value.tv_usec =
		cfg.usec_delay.it_interval.tv_usec = interval_us;
	}
}

/* run with stdout/stderr sent to /dev/null (banner and statistics) */
static int run_quiet(void)
{
	int out = dup(1), err = dup(2), null = open("/dev/null", O_WRONLY), rc;

	fflush(stdout); fflush(stderr);
	dup2(null, 1); dup2(null, 2);
	rc = hping_run();
	fflush(stdout); fflush(stderr);
	dup2(out, 1); dup2(err, 2);
	close(out); close(err); close(null);
	return rc;
}

/* ------------------------------------------------------------------ */
/* tests                                                               */
/* ------------------------------------------------------------------ */

static void test_schedule_and_rtt(void)
{
	int rc;

	TEST("loop: probes at their deadlines, replies matched, late reply timeout");
	session_reset(1000000, 3);			/* -i u1000000 -c 3 */
	script_reply(1000000 + 37000, SPORT, 0x12);	/* answers probe 0 after 37 ms */
	script_reply(2000000 + 41000, SPORT + 1, 0x12);	/* answers probe 1 after 41 ms */
	rc = run_quiet();

	CHECK_EQ_INT(stub_send_calls, 3);
	CHECK_EQ_INT(stub_send_us[0], 1000000);
	CHECK_EQ_INT(stub_send_us[1], 2000000);
	CHECK_EQ_INT(stub_send_us[2], 3000000);
	CHECK_EQ_INT(ctx.stop_reason, HPING_STOP_SENT);
	/* the loop waited COUNTREACHED_TIMEOUT after the last probe */
	CHECK_EQ_INT(fake_now_us, 3000000 + COUNTREACHED_TIMEOUT * 1000000LL);
	CHECK_EQ_INT(stats.sent, 3);
	CHECK_EQ_INT(stats.received, 2);
	CHECK_EQ_INT(stats.duplicates, 0);
	CHECK_EQ_INT(stats.unmatched, 0);
	CHECK_EQ_INT(hping_stats_unique(&stats), 2);
	CHECK_EQ_INT(hping_stats_loss_percent(&stats), 33);
	CHECK_EQ_INT(stats.rtt_samples, 2);
	CHECK((int)(stats.rtt_min * 1000) == 37000);
	CHECK((int)(stats.rtt_max * 1000) == 41000);
	CHECK((int)(stats.rtt_avg * 1000) == 39000);
	CHECK_EQ_INT(rc, 0);				/* replies received */
	CHECK_EQ_INT(ctx.tcp_exitcode, 0x12);
	/* the probes themselves: TCP SYN to port 80 from consecutive ports */
	CHECK_EQ_INT(stub_last_size, 20);
	CHECK_EQ_INT((stub_last_packet[0] << 8) | stub_last_packet[1], SPORT + 2);
	CHECK_EQ_INT((stub_last_packet[2] << 8) | stub_last_packet[3], DPORT);
	CHECK_EQ_INT(stub_last_packet[13], TH_SYN);
	hping_destroy();
}

static void test_count_reached_by_replies(void)
{
	int rc;

	TEST("loop: --count answered stops before the next probe");
	session_reset(1000000, 2);
	script_reply(1000000 + 10000, SPORT, 0x12);
	script_reply(2000000 + 10000, SPORT + 1, 0x12);
	rc = run_quiet();
	CHECK_EQ_INT(stub_send_calls, 2);
	CHECK_EQ_INT(ctx.stop_reason, HPING_STOP_COUNT);
	CHECK_EQ_INT(fake_now_us, 2010000);		/* right at the 2nd reply */
	CHECK_EQ_INT(stats.received, 2);
	CHECK_EQ_INT(hping_stats_loss_percent(&stats), 0);
	CHECK_EQ_INT(rc, 0);
	hping_destroy();
}

static void test_duplicates_and_late(void)
{
	int rc;

	TEST("loop: duplicate replies are counted but do not answer more probes");
	session_reset(1000000, 2);
	script_reply(1000000 + 10000, SPORT, 0x12);
	script_reply(1000000 + 20000, SPORT, 0x12);	/* same probe again */
	script_reply(1000000 + 30000, SPORT, 0x12);
	rc = run_quiet();
	/* three replies for probe 0: the count (2) is not reached by them,
	 * probe 1 is sent and never answered */
	CHECK_EQ_INT(stub_send_calls, 2);
	CHECK_EQ_INT(ctx.stop_reason, HPING_STOP_SENT);
	CHECK_EQ_INT(stats.received, 3);
	CHECK_EQ_INT(stats.duplicates, 2);
	CHECK_EQ_INT(hping_stats_unique(&stats), 1);
	CHECK_EQ_INT(hping_stats_loss_percent(&stats), 50);
	CHECK_EQ_INT(stats.rtt_samples, 3);		/* every match has an RTT */
	CHECK_EQ_INT(rc, 0);
	hping_destroy();

	TEST("loop: a reply for an unknown probe is unmatched, not a loss fix");
	session_reset(1000000, 1);
	script_reply(1000000 + 10000, SPORT + 7, 0x12);	/* never sent */
	rc = run_quiet();
	CHECK_EQ_INT(stats.received, 1);
	CHECK_EQ_INT(stats.unmatched, 1);
	CHECK_EQ_INT(hping_stats_unique(&stats), 0);
	CHECK_EQ_INT(hping_stats_loss_percent(&stats), 100);
	CHECK_EQ_INT(stats.rtt_samples, 0);
	CHECK_EQ_INT(rc, 0); /* historical: any received reply = exit 0 */
	hping_destroy();
}

static void test_interrupt(void)
{
	int rc;

	TEST("loop: interrupt (SIGINT) ends an endless run and reports");
	session_reset(1000000, -1);			/* forever */
	stop_after_waits = 4;
	rc = run_quiet();
	CHECK_EQ_INT(ctx.stop_reason, HPING_STOP_SIGNAL);
	CHECK(stub_send_calls >= 3 && stub_send_calls <= 4);
	CHECK_EQ_INT(stats.received, 0);
	CHECK_EQ_INT(hping_stats_loss_percent(&stats), 100);
	CHECK_EQ_INT(rc, 1);				/* nothing received */
	hping_destroy();

	TEST("loop: --tcpexitcode returns the flags of the last reply");
	session_reset(1000000, 1);
	cfg.opt_tcpexitcode = TRUE;
	script_reply(1000000 + 5000, SPORT, 0x14);	/* RST+ACK */
	rc = run_quiet();
	CHECK_EQ_INT(rc, 0x14);
	hping_destroy();
}

static void test_send_error(void)
{
	int rc;

	TEST("loop: a send error stops the run with exit status 1");
	session_reset(1000000, 5);
	stub_send_fail = 1;
	rc = run_quiet();
	CHECK_EQ_INT(ctx.stop_reason, HPING_STOP_ERROR);
	CHECK_EQ_INT(stub_send_calls, 1);
	CHECK_EQ_INT(stats.sent, 0);			/* not counted as sent */
	CHECK_EQ_INT(rc, 1);
	hping_destroy();
}

static void test_zero_interval_and_seconds(void)
{
	int rc;

	TEST("loop: -i u0 sends back to back");
	session_reset(0, 5);
	rc = run_quiet();
	CHECK_EQ_INT(stub_send_calls, 5);
	CHECK_EQ_INT(stub_send_us[4], 1000000);		/* all at the same instant */
	CHECK_EQ_INT(ctx.stop_reason, HPING_STOP_SENT);
	CHECK_EQ_INT(rc, 1);
	hping_destroy();

	TEST("loop: -i 2 (seconds) spaces probes by 2 s");
	session_reset(-1, 3);
	cfg.sending_wait = 2;
	rc = run_quiet();
	CHECK_EQ_INT(stub_send_us[0], 1000000);
	CHECK_EQ_INT(stub_send_us[1], 3000000);
	CHECK_EQ_INT(stub_send_us[2], 5000000);
	CHECK_EQ_INT(hping_send_interval_us(), 2000000);
	hping_destroy();
}

static void test_wall_clock_jump(void)
{
	int rc;

	TEST("clock: a wall clock jump between probe and reply leaves the RTT alone");
	session_reset(1000000, 1);
	script_reply(1000000 + 25000, SPORT, 0x12);
	/* the wall clock jumps one hour ahead right after the probe */
	rc = run_quiet();
	CHECK_EQ_INT(rc, 0);
	CHECK((int)(stats.rtt_min * 1000) == 25000);
	fake_wall_offset_us += 3600LL * 1000000LL;
	CHECK((int)(stats.rtt_min * 1000) == 25000);
	/* milliseconds() (ICMP timestamp) follows the wall clock, mstime()
	 * (elapsed time) the monotonic one */
	CHECK_EQ_INT(mstime(), fake_now_us / 1000);
	CHECK_EQ_INT(milliseconds(), ((fake_now_us + fake_wall_offset_us) / 1000000 % 86400) * 1000
			+ ((fake_now_us + fake_wall_offset_us) % 1000000) / 1000);
	hping_destroy();

	TEST("clock: delaytable entries carry the monotonic send time");
	session_reset(1000000, 1);
	fake_now_us = 5000000;
	delaytable_add(9, 1234, S_SENT);
	fake_now_us = 5000000 + 123456;
	{
		int seq = 9; float ms = 0;
		CHECK_EQ_INT(rtt(&seq, 0, &ms), S_SENT);
		CHECK((int)(ms * 1000) == 123456);
		CHECK_EQ_INT(rtt(&seq, 0, &ms), S_RECV);	/* second lookup: dup */
		seq = 77;
		CHECK_EQ_INT(rtt(&seq, 0, &ms), S_UNKNOWN);
	}
	hping_destroy();
}

static unsigned int fixed_rand(void *arg) { return *(unsigned int*) arg; }

static void test_random_injection(void)
{
	unsigned int value = 0x12345678;

	TEST("random: the injected source feeds TCP sequence/ack numbers");
	session_reset(0, 1);
	hping_random_set(fixed_rand, &value);
	run_quiet();
	CHECK_EQ_INT(stub_send_calls, 1);
	CHECK_EQ_INT(stub_last_packet[4], 0x12);	/* seq */
	CHECK_EQ_INT(stub_last_packet[7], 0x78);
	CHECK_EQ_INT(stub_last_packet[8], 0x12);	/* ack */
	CHECK_EQ_INT(hping_rand(), 0x12345678);
	hping_destroy();
}

static int fd_is_open(int fd)
{
	return fd >= 0 && fcntl(fd, F_GETFD) != -1;
}

static void test_init_failure_cleanup(void)
{
	int fds[2], raw;

	TEST("lifecycle: hping_destroy() releases what a partial init opened");
	session_reset(1000000, 1);
	/* pretend hping_init() got this far: raw socket and wake up pipe
	 * open (plain descriptors here, no network) */
	raw = open("/dev/null", O_RDONLY);
	CHECK(pipe(fds) == 0);
	ctx.sockraw = raw;
	ctx.wake_fd[0] = fds[0];
	ctx.wake_fd[1] = fds[1];
	cfg.opt_scanports = strdup("1-10");
	cfg.apd_send = strdup("ip()");
	hping_destroy();
	CHECK_EQ_INT(ctx.sockraw, -1);
	CHECK_EQ_INT(ctx.wake_fd[0], -1);
	CHECK_EQ_INT(ctx.wake_fd[1], -1);
	CHECK(!fd_is_open(raw));
	CHECK(!fd_is_open(fds[0]));
	CHECK(!fd_is_open(fds[1]));
	CHECK(cfg.apd_send == NULL);
	CHECK_EQ_STR(cfg.opt_scanports, "");
	hping_destroy(); /* idempotent */
	CHECK_EQ_INT(ctx.sockraw, -1);

	TEST("lifecycle: hping_stop() keeps the first reason");
	hping_context_init(&ctx);
	hping_stop(HPING_STOP_COUNT);
	hping_stop(HPING_STOP_SIGNAL);
	CHECK_EQ_INT(ctx.stop_reason, HPING_STOP_COUNT);
	CHECK(hping_stop_requested());
}

/* ---- the real I/O path: poll(2) on a savefile, non blocking pcap ---- */

static const char *write_reply_savefile(int nreplies)
{
	static char path[128];
	pcap_t *dead = pcap_open_dead(DLT_RAW, 65535);
	pcap_dumper_t *dump;
	struct pcap_pkthdr h;
	int i;

	snprintf(path, sizeof(path), "/tmp/hping-test-loop-%ld.pcap", (long)getpid());
	dump = pcap_dump_open(dead, path);
	if (!dump) {
		fprintf(stderr, "pcap_dump_open: %s\n", pcap_geterr(dead));
		exit(2);
	}
	memset(&h, 0, sizeof(h));
	for (i = 0; i < nreplies; i++) {
		struct scripted f;
		unsigned short ck;
		int hlen;

		memset(&f, 0, sizeof(f));
		hlen = tu_build_ip(f.data, 0, 40, 6, REMOTE, LOCAL);
		tu_build_tcp(f.data + hlen, DPORT, SPORT + i, 0x12, 5);
		ck = tu_l4_cksum(REMOTE, LOCAL, 6, f.data + hlen, 20);
		memcpy(f.data + hlen + 16, &ck, 2);
		h.ts.tv_sec = i;
		h.caplen = h.len = hlen + 20;
		pcap_dump((u_char*)dump, &h, f.data);
	}
	pcap_dump_close(dump);
	pcap_close(dead);
	return path;
}

static void test_real_pcap_io(void)
{
	const char *path = write_reply_savefile(2);
	char err[PCAP_ERRBUF_SIZE];
	int rc;

	TEST("loop: the default I/O (poll + non blocking pcap) reads a savefile to its end");
	session_reset(1000000, 5);
	hping_io_pcap(&ctx.io);			/* the real wait/read */
	ctx.pcapfp = pcap_open_offline(path, err);
	CHECK(ctx.pcapfp != NULL);
	if (!ctx.pcapfp) return;
	pcap_setnonblock(ctx.pcapfp, 1, err);
	ctx.pcap_fd = pcap_get_selectable_fd(ctx.pcapfp);
	rc = run_quiet();
	/* probe 0 goes out, both replies are read at once (a file is always
	 * readable): the first matches probe 0, the second answers a probe
	 * not sent yet (unmatched), then the end of the file stops the run */
	CHECK_EQ_INT(ctx.stop_reason, HPING_STOP_EOF);
	CHECK_EQ_INT(stats.sent, 1);
	CHECK_EQ_INT(stats.received, 2);
	CHECK_EQ_INT(stats.unmatched, 1);
	CHECK_EQ_INT(hping_stats_unique(&stats), 1);
	CHECK_EQ_INT(rc, 0);
	hping_destroy();				/* closes the handle */
	CHECK(ctx.pcapfp == NULL);
	CHECK_EQ_INT(ctx.pcap_fd, -1);
	unlink(path);
}

/* ---- the real signal path: SIGINT wakes poll(2) up ---- */

static void on_alarm(int signo)
{
	(void) signo;
	raise(SIGINT); /* async-signal-safe; hping's handler sets its flag */
}

static void test_real_signal_wakeup(void)
{
	struct itimerval it;
	struct timeval t0, t1;
	long long elapsed_us;
	int rc;

	TEST("loop: a real SIGINT interrupts a long poll() through the wake up pipe");
	session_reset(2000000, -1);			/* -i u2000000, forever */
	hping_clock_system(&ctx);			/* real clocks */
	hping_io_pcap(&ctx.io);
	ctx.pcap_fd = -1;
	ctx.pcap_poll_ms = 5000;			/* would sleep 2 s otherwise */
	CHECK_EQ_INT(hping_signals_install(), 0);
	CHECK(ctx.wake_fd[0] >= 0 && ctx.wake_fd[1] >= 0);
	signal(SIGALRM, on_alarm);
	memset(&it, 0, sizeof(it));
	it.it_value.tv_usec = 50000;			/* SIGINT after 50 ms */
	setitimer(ITIMER_REAL, &it, NULL);
	gettimeofday(&t0, NULL);
	rc = run_quiet();
	gettimeofday(&t1, NULL);
	elapsed_us = (t1.tv_sec - t0.tv_sec) * 1000000LL + (t1.tv_usec - t0.tv_usec);
	CHECK_EQ_INT(ctx.stop_reason, HPING_STOP_SIGNAL);
	CHECK(elapsed_us < 1500000);			/* not the 2 s interval */
	CHECK_EQ_INT(stats.sent, 1);
	CHECK_EQ_INT(rc, 1);
	signal(SIGALRM, SIG_DFL);
	hping_destroy();
	CHECK_EQ_INT(ctx.wake_fd[0], -1);
	CHECK_EQ_INT(ctx.signals_installed, 0);
}

int main(void)
{
	test_schedule_and_rtt();
	test_count_reached_by_replies();
	test_duplicates_and_late();
	test_interrupt();
	test_send_error();
	test_zero_interval_and_seconds();
	test_wall_clock_jump();
	test_random_injection();
	test_init_failure_cleanup();
	test_real_pcap_io();
	test_real_signal_wakeup();
	return tu_report("test_loop");
}
