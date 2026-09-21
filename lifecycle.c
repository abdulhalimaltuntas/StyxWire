/* lifecycle.c -- init / run / stop / destroy of the command line tool.
 *
 * Before this file existed packets were sent from a SIGALRM handler and
 * SIGINT/SIGTERM printed the statistics and called exit() from signal
 * context. Now:
 *
 *   hping_init()     resolves addresses, opens the raw socket and the
 *                    capture handle, installs the signal handlers. On a
 *                    failure it returns -1 with the resources it managed
 *                    to open still held, so that hping_destroy() releases
 *                    them: partial initialisation, user interruption and
 *                    normal completion all end in hping_destroy().
 *   hping_run()      one poll(2) based loop: probes are sent when their
 *                    deadline on the monotonic clock is due, replies are
 *                    read when the capture descriptor is readable, pending
 *                    signals are handled in between. Returns the exit
 *                    status. Flood, listen and scan modes have their own
 *                    loops but share the stop and destroy contract.
 *   hping_stop()     asks the loop to end; also what the signal handlers
 *                    do indirectly: they only set a flag and write one
 *                    byte to a pipe that wakes poll(2) up.
 *   hping_destroy()  closes descriptors, frees memory, restores signals.
 *
 * The waiting and reading primitives live behind ctx.io so that the tests
 * drive the loop with a fake clock and scripted frames (tests/test_loop.c).
 *
 * Portability: poll(2), pipe(2), sigaction(2) and clock_gettime(2) only
 * (POSIX.1-2001). pcap_get_selectable_fd() can return -1 on some capture
 * backends; the loop then polls the handle every ctx.pcap_poll_ms.
 *
 * Copyright (C) 1999 by Salvatore Sanfilippo (the initialisation steps
 * come from the historical main.c), GPL version 2. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hping2.h"
#include "globals.h"

/* ------------------------------------------------------------------ */
/* signals: flags and a wake up byte, nothing else                     */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t sig_stop = 0;	/* signal number, 0 = none */
static volatile sig_atomic_t sig_tstp = 0;	/* ctrl+z binding pending */

static void on_signal(int signo)
{
	int saved_errno = errno;

	if (signo == SIGTSTP)
		sig_tstp = 1;
	else
		sig_stop = signo;
	if (ctx.wake_fd[1] != -1) {
		char c = 1;
		ssize_t r = write(ctx.wake_fd[1], &c, 1);
		(void) r; /* a full pipe means poll() is awake anyway */
	}
	errno = saved_errno;
}

static int install_handler(int signo, void (*handler)(int))
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0; /* no SA_RESTART: blocking calls return EINTR */
	return sigaction(signo, &act, NULL);
}

int hping_signals_install(void)
{
	if (pipe(ctx.wake_fd) == -1) {
		perror("[hping_init] pipe");
		return -1;
	}
	fcntl(ctx.wake_fd[0], F_SETFL, O_NONBLOCK);
	fcntl(ctx.wake_fd[1], F_SETFL, O_NONBLOCK);
	fcntl(ctx.wake_fd[0], F_SETFD, FD_CLOEXEC);
	fcntl(ctx.wake_fd[1], F_SETFD, FD_CLOEXEC);
	sig_stop = 0;
	sig_tstp = 0;
	if (install_handler(SIGINT, on_signal) == -1 ||
	    install_handler(SIGTERM, on_signal) == -1)
		return -1;
	/* ctrl+z is bound to the destination port / TTL unless --unbind */
	if (cfg.ctrlzbind != BIND_NONE)
		install_handler(SIGTSTP, on_signal);
	ctx.signals_installed = 1;
	return 0;
}

void hping_signals_restore(void)
{
	if (ctx.signals_installed) {
		install_handler(SIGINT, SIG_DFL);
		install_handler(SIGTERM, SIG_DFL);
		install_handler(SIGTSTP, SIG_DFL);
		ctx.signals_installed = 0;
	}
	if (ctx.wake_fd[0] != -1) {
		close(ctx.wake_fd[0]);
		ctx.wake_fd[0] = -1;
	}
	if (ctx.wake_fd[1] != -1) {
		close(ctx.wake_fd[1]);
		ctx.wake_fd[1] = -1;
	}
}

static void drain_wake_pipe(void)
{
	char buf[64];

	if (ctx.wake_fd[0] == -1)
		return;
	while (read(ctx.wake_fd[0], buf, sizeof(buf)) > 0)
		;
}

/* Move the signal flags into the loop state. Called from normal context
 * only, so everything that follows (output, memory, exit) is safe. */
static void handle_pending_signals(void)
{
	if (sig_tstp) {
		sig_tstp = 0;
		inc_destparm();
	}
	if (sig_stop && ctx.stop_reason == HPING_STOP_NONE)
		ctx.stop_reason = HPING_STOP_SIGNAL;
}

void hping_stop(int reason)
{
	if (ctx.stop_reason == HPING_STOP_NONE)
		ctx.stop_reason = reason;
}

int hping_stop_requested(void)
{
	return ctx.stop_reason != HPING_STOP_NONE || sig_stop != 0;
}

/* ------------------------------------------------------------------ */
/* default I/O: poll the capture handle and the wake up pipe           */
/* ------------------------------------------------------------------ */

static int pcap_io_wait(long long timeout_us)
{
	struct pollfd fds[2];
	int n = 0, ms, r, pcap_idx = -1;

	if (ctx.pcap_fd >= 0) {
		fds[n].fd = ctx.pcap_fd;
		fds[n].events = POLLIN;
		fds[n].revents = 0;
		pcap_idx = n++;
	}
	if (ctx.wake_fd[0] >= 0) {
		fds[n].fd = ctx.wake_fd[0];
		fds[n].events = POLLIN;
		fds[n].revents = 0;
		n++;
	}
	/* poll(2) has millisecond granularity: below one millisecond do
	 * not sleep at all, that is what "as fast as the timer allows"
	 * (--faster) means here */
	if (timeout_us < 0)
		ms = -1;
	else if (timeout_us < 1000)
		ms = 0;
	else if (timeout_us / 1000 > 1000000)
		ms = 1000000;
	else
		ms = (int) (timeout_us / 1000);
	/* no selectable descriptor: look at the handle periodically */
	if (pcap_idx == -1 && (ms < 0 || ms > ctx.pcap_poll_ms))
		ms = ctx.pcap_poll_ms;

	r = poll(fds, n, ms);
	if (r < 0)
		return errno == EINTR ? 0 : -1;
	drain_wake_pipe();
	if (pcap_idx == -1)
		return 1; /* try a non blocking read */
	return (fds[pcap_idx].revents & (POLLIN|POLLERR|POLLHUP)) ? 1 : 0;
}

static int pcap_io_read(char *buf, int size)
{
	if (size < 0)
		return -1;
	return pcap_recv(buf, (unsigned int) size);
}

static const struct hping_io_ops pcap_io_ops = { pcap_io_wait, pcap_io_read };

/* The default I/O operations (capture handle + wake up pipe) */
void hping_io_pcap(struct hping_io_ops *io)
{
	*io = pcap_io_ops;
}

/* The sending interval on the monotonic clock. 0 means "as fast as the
 * loop turns", which is what -i u0 always meant; -i 0 (seconds) used to
 * cancel the timer after the first probe, it now behaves like -i u0. */
long long hping_send_interval_us(void)
{
	if (cfg.opt_waitinusec)
		return (long long) cfg.usec_delay.it_interval.tv_usec;
	return (long long) cfg.sending_wait * 1000000LL;
}

/* ------------------------------------------------------------------ */
/* init / destroy                                                      */
/* ------------------------------------------------------------------ */

static int resolve_or_fail(struct sockaddr_in *sa, char *name)
{
	if (resolve_addr((struct sockaddr*) sa, name) == -1) {
		fprintf(stderr, "Unable to resolve '%s'\n", name);
		return -1;
	}
	return 0;
}

int hping_init(void)
{
	ctx.stop_reason = HPING_STOP_NONE;
	ctx.end_deadline_us = -1;
	if (ctx.io.wait == NULL) /* a test may have installed its own */
		ctx.io = pcap_io_ops;

	/* reverse sign */
	if (cfg.opt_sign || cfg.opt_listenmode) {
		char *src = cfg.sign+strlen(cfg.sign)-1; /* last char before '\0' */
		char *dst = ctx.rsign;

		while(src>=cfg.sign)
			*dst++ = *src--;
		*dst = '\0';
		if (cfg.opt_debug)
			printf("DEBUG: reverse sign: %s\n", ctx.rsign);
	}

	/* get target address before interface processing */
	if ((!cfg.opt_listenmode && !cfg.opt_safe) && !cfg.opt_rand_dest) {
		if (resolve_or_fail(&ctx.remote, cfg.targetname) == -1)
			return -1;
	}

	if (cfg.opt_rand_dest) {
		strlcpy(ctx.targetstraddr, cfg.targetname, sizeof(ctx.targetstraddr));
	} else {
		strlcpy(ctx.targetstraddr, inet_ntoa(ctx.remote.sin_addr),
			sizeof(ctx.targetstraddr));
	}

	/* get interface's name and address */
	if ( get_if_name() == -1 ) {
		fprintf(stderr, "[main] no such device\n");
		return -1;
	}

	if (cfg.opt_verbose || cfg.opt_debug) {
		printf("using %s, addr: %s, MTU: %d\n",
			cfg.ifname, ctx.ifstraddr, ctx.h_if_mtu);
	}

	/* open raw socket */
	ctx.sockraw = open_sockraw();
	if (ctx.sockraw == -1) {
		fprintf(stderr, "[main] can't open raw socket\n");
		return -1;
	}

	/* set SO_BROADCAST option */
	socket_broadcast(ctx.sockraw);
	/* set SO_IPHDRINCL option */
	socket_iphdrincl(ctx.sockraw);

	/* open sock packet or libpcap socket */
	if (open_pcap() == -1) {
		fprintf(stderr, "[main] open_pcap failed\n");
		return -1;
	}

	/* get physical layer header size */
	if ( get_linkhdr_size(cfg.ifname) == -1 ) {
		fprintf(stderr, "[main] physical layer header size unknown\n");
		return -1;
	}

	if (resolve_or_fail(&ctx.local, cfg.spoofaddr[0] ? cfg.spoofaddr : ctx.ifstraddr) == -1)
		return -1;
	if (resolve_or_fail(&ctx.icmp_ip_src, cfg.icmp_ip_srcip[0] ? cfg.icmp_ip_srcip : "1.2.3.4") == -1)
		return -1;
	if (resolve_or_fail(&ctx.icmp_ip_dst, cfg.icmp_ip_dstip[0] ? cfg.icmp_ip_dstip : "5.6.7.8") == -1)
		return -1;
	if (resolve_or_fail(&ctx.icmp_gw, cfg.icmp_gwip[0] ? cfg.icmp_gwip : "0.0.0.0") == -1)
		return -1;

	/* set initial source port */
	if (cfg.initsport == -1)
		cfg.initsport = ctx.src_port = 1024 + (hping_rand() % 2000);
	else
		ctx.src_port = cfg.initsport;

	if (hping_signals_install() == -1)
		return -1;
	return 0;
}

void hping_destroy(void)
{
	hping_signals_restore();
	if (ctx.pcapfp != NULL) {
		close_pcap();
		ctx.pcapfp = NULL;
		ctx.pcap_fd = -1;
	}
	if (ctx.sockraw != -1) {
		close(ctx.sockraw);
		ctx.sockraw = -1;
	}
	if (cfg.opt_scanports != NULL && cfg.opt_scanports[0] != '\0') {
		free(cfg.opt_scanports);
		cfg.opt_scanports = "";
	}
	free(cfg.apd_send);
	cfg.apd_send = NULL;
}

/* ------------------------------------------------------------------ */
/* run                                                                 */
/* ------------------------------------------------------------------ */

static void print_banner(void)
{
	char setflags[1024] = {'\0'};
	int hdr_size;

	if (cfg.opt_rawipmode) {
		strcat(setflags, "raw IP mode");
		hdr_size = IPHDR_SIZE;
	} else if (cfg.opt_icmpmode) {
		strcat(setflags, "icmp mode");
		hdr_size = IPHDR_SIZE + ICMPHDR_SIZE;
	} else if (cfg.opt_udpmode) {
		strcat(setflags, "udp mode");
		hdr_size = IPHDR_SIZE + UDPHDR_SIZE;
	} else {
		if (cfg.tcp_th_flags & TH_RST)  strcat(setflags, "R");
		if (cfg.tcp_th_flags & TH_SYN)  strcat(setflags, "S");
		if (cfg.tcp_th_flags & TH_ACK)  strcat(setflags, "A");
		if (cfg.tcp_th_flags & TH_FIN)  strcat(setflags, "F");
		if (cfg.tcp_th_flags & TH_PUSH) strcat(setflags, "P");
		if (cfg.tcp_th_flags & TH_URG)  strcat(setflags, "U");
		if (cfg.tcp_th_flags & TH_X)    strcat(setflags, "X");
		if (cfg.tcp_th_flags & TH_Y)    strcat(setflags, "Y");
		if (setflags[0] == '\0')    strcat(setflags, "NO FLAGS are");
		hdr_size = IPHDR_SIZE + TCPHDR_SIZE;
	}

	printf("HPING %s (%s %s): %s set, %d headers + %d data bytes\n",
		cfg.targetname,
		cfg.ifname,
		ctx.targetstraddr,
		setflags,
		hdr_size,
		cfg.data_size);
}

static void lock_memory(void)
{
	if (memlockall() == -1) {
		perror("[main] memlockall()");
		fprintf(stderr, "Warning: can't disable memory paging!\n");
	} else if (cfg.opt_verbose || cfg.opt_debug) {
		printf("Memory paging disabled\n");
	}
}

/* --count reached on the sending side: keep reading replies for
 * COUNTREACHED_TIMEOUT seconds, then stop */
static int all_probes_sent(void)
{
	return cfg.count != -1 && stats.sent >= (unsigned long long) cfg.count;
}

/* Send one probe and schedule the next one. Returns -1 on a send error. */
static int send_due_probe(long long now)
{
	long long interval = hping_send_interval_us();

	if (send_packet() == -1)
		return -1;
	if (all_probes_sent()) {
		ctx.end_deadline_us = now + (long long) COUNTREACHED_TIMEOUT * 1000000LL;
		return 0;
	}
	/* periodic, drift free; if the loop fell behind by more than one
	 * interval (blocked output, suspended process) do not burst */
	ctx.next_send_us += interval;
	if (ctx.next_send_us < now)
		ctx.next_send_us = now;
	return 0;
}

static int flood_loop(void)
{
	fprintf(stderr, "hping in flood mode, no replies will be shown\n");
	while (!hping_stop_requested()) {
		if (send_packet() == -1) {
			hping_stop(HPING_STOP_ERROR);
			break;
		}
		if (all_probes_sent()) {
			hping_stop(HPING_STOP_SENT);
			break;
		}
		if (sig_tstp)
			handle_pending_signals();
	}
	handle_pending_signals();
	return 0;
}

/* The event loop of the normal (TCP/UDP/ICMP/raw IP) mode. */
static int main_loop(void)
{
	ctx.next_send_us = hping_monotonic_us();
	ctx.end_deadline_us = -1;

	while (1) {
		long long now, timeout;
		int r;

		handle_pending_signals();
		if (ctx.stop_reason != HPING_STOP_NONE)
			break;

		now = hping_monotonic_us();
		if (ctx.end_deadline_us != -1 && now >= ctx.end_deadline_us) {
			hping_stop(HPING_STOP_SENT);
			break;
		}
		if (!all_probes_sent() && now >= ctx.next_send_us) {
			if (send_due_probe(now) == -1) {
				hping_stop(HPING_STOP_ERROR);
				break;
			}
			now = hping_monotonic_us();
		}

		/* how long may we sleep: until the next probe is due, or
		 * until the late replies deadline */
		if (!all_probes_sent())
			timeout = ctx.next_send_us - now;
		else
			timeout = ctx.end_deadline_us - now;
		if (timeout < 0)
			timeout = 0;

		r = ctx.io.wait(timeout);
		if (r < 0) {
			perror("[hping_run] waiting for packets");
			hping_stop(HPING_STOP_ERROR);
			break;
		}
		if (r > 0)
			wait_packet(); /* one frame; may call hping_stop() */
	}
	return 0;
}

int hping_run(void)
{
	if (cfg.opt_listenmode) {
		fprintf(stderr, "hping2 listen mode\n");
		lock_memory();
		listen_run();
	} else if (cfg.opt_scanmode) {
		fprintf(stderr, "Scanning %s (%s), port %s\n",
				cfg.targetname, ctx.targetstraddr, cfg.opt_scanports);
		return scan_run();
	} else {
		print_banner();
		if (cfg.opt_datafromfile || cfg.opt_sign)
			lock_memory();
		if (cfg.opt_flood)
			flood_loop();
		else
			main_loop();
	}
	hping_stats_print(stderr, cfg.targetname);
	if (ctx.stop_reason == HPING_STOP_ERROR)
		return 1;
	return hping_exit_code();
}
