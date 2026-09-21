/* parseoptions.c -- options handling
 * Copyright(C) 1999-2001 Salvatore Sanfilippo
 * Under GPL, see the COPYING file for more information about
 * the license. */

/* $Id: parseoptions.c,v 1.2 2004/06/18 09:53:11 antirez Exp $ */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "antigetopt.h"

#include "hping2.h"
#include "globals.h"

enum {	OPT_COUNT, OPT_INTERVAL, OPT_NUMERIC, OPT_QUIET, OPT_INTERFACE,
	OPT_HELP, OPT_VERSION, OPT_DESTPORT, OPT_BASEPORT, OPT_TTL, OPT_ID,
	OPT_WIN, OPT_SPOOF, OPT_FIN, OPT_SYN, OPT_RST, OPT_PUSH, OPT_ACK,
	OPT_URG, OPT_XMAS, OPT_YMAS, OPT_FRAG, OPT_MOREFRAG, OPT_DONTFRAG,
	OPT_FRAGOFF, OPT_TCPOFF, OPT_REL, OPT_DATA, OPT_RAWIP, OPT_ICMP,
	OPT_UDP, OPT_BIND, OPT_UNBIND, OPT_DEBUG, OPT_VERBOSE, OPT_WINID,
	OPT_KEEP, OPT_FILE, OPT_DUMP, OPT_PRINT, OPT_SIGN, OPT_LISTEN,
	OPT_SAFE, OPT_TRACEROUTE, OPT_TOS, OPT_MTU, OPT_SEQNUM, OPT_BADCKSUM,
	OPT_SETSEQ, OPT_SETACK, OPT_ICMPTYPE, OPT_ICMPCODE, OPT_END,
	OPT_RROUTE, OPT_IPPROTO, OPT_ICMP_IPVER, OPT_ICMP_IPHLEN,
	OPT_ICMP_IPLEN, OPT_ICMP_IPID, OPT_ICMP_IPPROTO, OPT_ICMP_CKSUM,
	OPT_ICMP_TS, OPT_ICMP_ADDR, OPT_TCPEXITCODE, OPT_FAST, OPT_TR_KEEP_TTL,
	OPT_TCP_TIMESTAMP, OPT_TR_STOP, OPT_TR_NO_RTT, OPT_ICMP_HELP,
	OPT_RAND_DEST, OPT_RAND_SOURCE, OPT_LSRR, OPT_SSRR, OPT_ROUTE_HELP,
	OPT_ICMP_IPSRC, OPT_ICMP_IPDST, OPT_ICMP_SRCPORT, OPT_ICMP_DSTPORT,
	OPT_ICMP_GW, OPT_FORCE_ICMP, OPT_APD_SEND, OPT_SCAN, OPT_FASTER,
	OPT_BEEP, OPT_FLOOD, OPT_CLOCK_SKEW, OPT_CS_WINDOW, OPT_CS_WINDOW_SHIFT,
        OPT_CS_VECTOR_LEN, OPT_DRY_RUN, OPT_JSON, OPT_READ };

static struct ago_optlist hping_optlist[] = {
	{ 'c',	"count",	OPT_COUNT,		AGO_NEEDARG },
	{ 'i',	"interval",	OPT_INTERVAL,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'n',	"numeric",	OPT_NUMERIC,		AGO_NOARG },
	{ 'q',	"quiet",	OPT_QUIET,		AGO_NOARG },
	{ 'I',	"interface",	OPT_INTERFACE,		AGO_NEEDARG },
	{ 'h',	"help",		OPT_HELP,		AGO_NOARG },
	{ 'v',	"version",	OPT_VERSION,		AGO_NOARG },
	{ 'p',	"destport",	OPT_DESTPORT,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 's',	"baseport",	OPT_BASEPORT,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 't',	"ttl",		OPT_TTL,		AGO_NEEDARG },
	{ 'N',	"id",		OPT_ID,			AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'w',	"win",		OPT_WIN,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'a',	"spoof",	OPT_SPOOF,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'F',	"fin",		OPT_FIN,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'S',	"syn",		OPT_SYN,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'R',	"rst",		OPT_RST,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'P',	"push",		OPT_PUSH,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'A',	"ack",		OPT_ACK,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'U',	"urg",		OPT_URG,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'X',	"xmas",		OPT_XMAS,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'Y',	"ymas",		OPT_YMAS,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'f',	"frag",		OPT_FRAG,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'x',	"morefrag",	OPT_MOREFRAG,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'y',	"dontfrag",	OPT_DONTFRAG,		AGO_NOARG },
	{ 'g',	"fragoff",	OPT_FRAGOFF,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'O',	"tcpoff",	OPT_TCPOFF,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'r',	"rel",		OPT_REL,		AGO_NOARG },
	{ 'd',	"data",		OPT_DATA,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '0',	"rawip",	OPT_RAWIP,		AGO_NOARG|AGO_EXCEPT0 },
	{ '1',	"icmp",		OPT_ICMP,		AGO_NOARG },
	{ '2',	"udp",		OPT_UDP,		AGO_NOARG },
	{ '8',	"scan",		OPT_SCAN,		AGO_NEEDARG },
	{ 'z',	"bind",		OPT_BIND,		AGO_NOARG },
	{ 'Z',	"unbind",	OPT_UNBIND,		AGO_NOARG },
	{ 'D',	"debug",	OPT_DEBUG,		AGO_NOARG },
	{ 'V',	"verbose",	OPT_VERBOSE,		AGO_NOARG },
	{ 'W',	"winid",	OPT_WINID,		AGO_NOARG },
	{ 'k',	"keep",		OPT_KEEP,		AGO_NOARG },
	{ 'E',	"file",		OPT_FILE,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'j',	"dump",		OPT_DUMP,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'J',	"print",	OPT_PRINT,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'e',	"sign",		OPT_SIGN,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '9',	"listen",	OPT_LISTEN,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'B',	"safe",		OPT_SAFE,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'T',	"traceroute",	OPT_TRACEROUTE,		AGO_NOARG },
	{ 'o',	"tos",		OPT_TOS,		AGO_NEEDARG },
	{ 'm',	"mtu",		OPT_MTU,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'Q',	"seqnum",	OPT_SEQNUM,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'b',	"badcksum",	OPT_BADCKSUM,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'M',	"setseq",	OPT_SETSEQ,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'L',	"setack",	OPT_SETACK,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'C',	"icmptype",	OPT_ICMPTYPE,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'K',	"icmpcode",	OPT_ICMPCODE,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'u',	"end",		OPT_END,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'G',	"rroute",	OPT_RROUTE,		AGO_NOARG },
	{ 'H',	"ipproto",	OPT_IPPROTO,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0',	"icmp-help",	OPT_ICMP_HELP,		AGO_NOARG },
	{ '\0',	"icmp-ipver",	OPT_ICMP_IPVER,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0',	"icmp-iphlen",	OPT_ICMP_IPHLEN, 	AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "icmp-iplen",	OPT_ICMP_IPLEN,	 	AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0',	"icmp-ipid",	OPT_ICMP_IPID,	 	AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0',	"icmp-ipproto",	OPT_ICMP_IPPROTO, 	AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "icmp-cksum",	OPT_ICMP_CKSUM,   	AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0',	"icmp-ts",	OPT_ICMP_TS,		AGO_NOARG },
	{ '\0', "icmp-addr",	OPT_ICMP_ADDR,		AGO_NOARG },
	{ '\0', "tcpexitcode",	OPT_TCPEXITCODE,	AGO_NOARG },
	{ '\0',	"fast",		OPT_FAST,		AGO_NOARG|AGO_EXCEPT0 },
	{ '\0',	"faster",	OPT_FASTER,		AGO_NOARG|AGO_EXCEPT0 },
	{ '\0',	"tr-keep-ttl",	OPT_TR_KEEP_TTL,	AGO_NOARG },
	{ '\0', "tcp-timestamp",OPT_TCP_TIMESTAMP,	AGO_NOARG },
	{ '\0', "tr-stop",	OPT_TR_STOP,		AGO_NOARG },
	{ '\0',	"tr-no-rtt",	OPT_TR_NO_RTT,		AGO_NOARG },
	{ '\0', "rand-dest",	OPT_RAND_DEST,		AGO_NOARG },
	{ '\0', "rand-source",	OPT_RAND_SOURCE,	AGO_NOARG },
	{ '\0', "lsrr",		OPT_LSRR, 		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "ssrr",		OPT_SSRR, 		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "route-help",   OPT_ROUTE_HELP,		AGO_NOARG },
	{ '\0', "apd-send",	OPT_APD_SEND,		AGO_NEEDARG },
	{ '\0', "icmp-ipsrc",	OPT_ICMP_IPSRC,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "icmp-ipdst",	OPT_ICMP_IPDST,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "icmp-gw",	OPT_ICMP_GW,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "icmp-srcport", OPT_ICMP_SRCPORT,	AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "icmp-dstport", OPT_ICMP_DSTPORT,	AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "force-icmp",	OPT_FORCE_ICMP,		AGO_NOARG },
	{ '\0', "beep",		OPT_BEEP,		AGO_NOARG },
	{ '\0', "flood",	OPT_FLOOD,		AGO_NOARG },
	{ '\0', "dry-run",	OPT_DRY_RUN,		AGO_NOARG },
	{ '\0', "json",	OPT_JSON,		AGO_NOARG },
	{ '\0',	"read",		OPT_READ,		AGO_NEEDARG },
	{ '\0', "clock-skew",	OPT_CLOCK_SKEW,		AGO_NOARG },
	{ '\0', "clock-skew-win", OPT_CS_WINDOW,	AGO_NEEDARG},
	{ '\0', "clock-skew-win-shift", OPT_CS_WINDOW_SHIFT,	AGO_NEEDARG},
	{ '\0', "clock-skew-packets-per-sample", OPT_CS_VECTOR_LEN,AGO_NEEDARG},
	AGO_LIST_TERM
};

/* The following var is turned to 1 if the -i option is used.
 * This allows to assign a different delay default value if
 * the scanning mode is selected. */
static int delay_changed = 0;

static int suidtester(void)
{
	return (getuid() != geteuid());
}

/* Numeric option arguments.
 *
 * Every value is parsed with strtol()/strtoul() semantics (decimal, 0x
 * hex, 0 octal), must be entirely consumed and must fit the range given
 * by the caller, which is the width of the protocol field the value ends
 * up in. A bad value is a usage error: a diagnostic naming the option,
 * the value and the accepted range is printed and styxwire exits with 1. */
/* Set by bad_number(): parse_options() checks it after every option and
 * returns HPING_PARSE_ERROR (the diagnostic was already printed). */
static int parse_failed = 0;

static void bad_number(const char *opt, const char *s, const char *why,
		       long long min, unsigned long long max)
{
	fprintf(stderr, "styxwire: option %s: invalid value '%s' (%s; "
		"expected a number in the range %lld..%llu)\n",
		opt, s, why, min, max);
	parse_failed = 1;
}

static long opt_num(const char *opt, const char *s, long min, long max)
{
	char *end;
	long v;

	if (s == NULL || *s == '\0') {
		bad_number(opt, s ? s : "", "empty", min, max);
		return min;
	}
	errno = 0;
	v = strtol(s, &end, 0);
	if (end == s || *end != '\0') {
		bad_number(opt, s, "not a number", min, max);
		return min;
	}
	if (errno == ERANGE || v < min || v > max) {
		bad_number(opt, s, "out of range", min, max);
		return min;
	}
	return v;
}

static unsigned long opt_unum(const char *opt, const char *s,
			      unsigned long max)
{
	char *end;
	unsigned long v;

	if (s == NULL || *s == '\0') {
		bad_number(opt, s ? s : "", "empty", 0, max);
		return 0;
	}
	if (*s == '-') {
		bad_number(opt, s, "negative", 0, max);
		return 0;
	}
	errno = 0;
	v = strtoul(s, &end, 0);
	if (end == s || *end != '\0') {
		bad_number(opt, s, "not a number", 0, max);
		return 0;
	}
	if (errno == ERANGE || v > max) {
		bad_number(opt, s, "out of range", 0, max);
		return 0;
	}
	return v;
}

/* Parse a --lsrr/--ssrr route ("[ptr:]IP1[/IP2...]") into the IP option
 * buffer 'route'. Returns 0, or -1 on a syntax error (message printed). */
int parse_route(unsigned char *route, unsigned int *route_len, const char *arg)
{
    struct in_addr ip;
    unsigned int i = 0;
    unsigned int j;
    unsigned int n = 0;
    unsigned int route_ptr = 256;
    char c;
    char str[1024]; /* tokenised in place: work on a copy of the argument */

    if (strlen(arg) >= sizeof(str)) {
        fprintf(stderr, "styxwire: route too long\n");
        return -1;
    }
    strcpy(str, arg);
    route += 3;
    while (str[i] != '\0')
    {
        for (j = i; isalnum(str[j]) || str[j] == '.'; j++);
        switch(c = str[j])
        {
            case '\0':
            case '/':
                if (n >= 62)
                {
                    fprintf(stderr, "styxwire: too long route\n");
                    return -1;
                }
                str[j] = '\0';
                if (inet_aton(str+i, &ip))
                {
                    memcpy(route+4*n, &ip.s_addr, 4);
                    n++;
                    if (c == '/')
                        str[j++] = '/';
                    break;
                }
                fprintf(stderr, "styxwire: invalid IP address in route: '%s'\n", str+i);
                return -1;
            case ':':
                if ((!i) && j && j < 4)
                {
                    sscanf(str, "%u:%n", &route_ptr, &i);
                    if (i == ++j)
                    {
                        if (route_ptr < 256)
                            break;
                    }
                }
            default:
                fprintf(stderr, "styxwire: invalid route syntax (try --route-help)\n");
                return -1;
        }
        i = j;
    }
    if (route_ptr == 256)
        route[-1] = (unsigned char) ( n ? 8 : 4 );
    else
        route[-1] = (unsigned char) route_ptr;
    *route_len = 4*n + 3;
    route[-2] = (unsigned char) *route_len;
    return 0;
}

/* Fill cfg from the command line.
 *
 * Returns HPING_PARSE_OK, HPING_PARSE_DONE when the command line only
 * asked for a help/version text (already printed: exit 0), or
 * HPING_PARSE_ERROR after printing a diagnostic on stderr (exit 1).
 * Nothing is sent and no socket is opened here; --apd-send is stored in
 * cfg.apd_send for main() to run. Callable more than once (tests). */
int parse_options(int argc, char **argv)
{
	int src_ttl_set = 0;
	int targethost_set = 0;
	int o;

	parse_failed = 0;
	delay_changed = 0;
	antigetopt(0, NULL, NULL); /* reset the parser state */
	if (argc < 2) {
		fprintf(stderr, "styxwire: missing host argument\n"
			"Try `styxwire --help' for more information.\n");
		return HPING_PARSE_ERROR;
	}

	ago_set_exception(0, suidtester, "Option disabled when setuid");

	while ((o = antigetopt(argc, argv, hping_optlist)) != AGO_EOF) {
		switch(o) {
		case AGO_UNKNOWN:
		case AGO_REQARG:
		case AGO_AMBIG:
			ago_gnu_error("styxwire", o);
			fprintf(stderr, "Try styxwire --help\n");
			return HPING_PARSE_ERROR;
		case AGO_ALONE:
			if (targethost_set == 1) {
				fprintf(stderr, "styxwire: you must specify only "
						"one target host at a time\n");
				return HPING_PARSE_ERROR;
			} else {
				strlcpy(cfg.targetname, ago_optarg, 1024);
				targethost_set = 1;
			}
			break;
		case OPT_COUNT:
			cfg.count = opt_num("-c/--count", ago_optarg, 1, INT_MAX);
			break;
		case OPT_INTERVAL:
			delay_changed = 1;
			if (*ago_optarg == 'u') {
				cfg.opt_waitinusec = TRUE;
				cfg.usec_delay.it_value.tv_sec =
				cfg.usec_delay.it_interval.tv_sec = 0;
				cfg.usec_delay.it_value.tv_usec = 
				cfg.usec_delay.it_interval.tv_usec =
					opt_num("-i/--interval", ago_optarg+1,
						0, 999999999L);
			}
			else
				cfg.sending_wait = opt_num("-i/--interval",
						ago_optarg, 0, INT_MAX);
			break;
		case OPT_NUMERIC:
			cfg.opt_numeric = TRUE;
			break;
		case OPT_QUIET:
			cfg.opt_quiet = TRUE;
			break;
		case OPT_INTERFACE:
			strlcpy (cfg.ifname, ago_optarg, 1024);
			break;
		case OPT_HELP:
			show_usage();
			return HPING_PARSE_DONE;
		case OPT_VERSION:
			show_version();
			return HPING_PARSE_DONE;
		case OPT_DESTPORT:
			if (*ago_optarg == '+')
			{
				cfg.opt_incdport = TRUE;
				ago_optarg++;
			}
			if (*ago_optarg == '+')
			{
				cfg.opt_force_incdport = TRUE;
				ago_optarg++;
			}
			cfg.base_dst_port = cfg.dst_port = opt_num("-p/--destport", ago_optarg, 0, 65535);
			break;
		case OPT_BASEPORT:
			cfg.initsport = opt_num("-s/--baseport", ago_optarg, 0, 65535);
			break;
		case OPT_TTL:
			cfg.src_ttl = opt_num("-t/--ttl", ago_optarg, 0, 255);
			src_ttl_set = 1;
			break;
		case OPT_ID:
			cfg.src_id = opt_num("-N/--id", ago_optarg, 0, 65535);
			break;
		case OPT_WIN:
			cfg.src_winsize = opt_num("-w/--win", ago_optarg, 0, 65535);
			break;
		case OPT_SPOOF:
			strlcpy (cfg.spoofaddr, ago_optarg, 1024);
			break;
		case OPT_FIN:
			cfg.tcp_th_flags |= TH_FIN;
			break;
		case OPT_SYN:
			cfg.tcp_th_flags |= TH_SYN;
			break;
		case OPT_RST:
			cfg.tcp_th_flags |= TH_RST;
			break;
		case OPT_PUSH:
			cfg.tcp_th_flags |= TH_PUSH;
			break;
		case OPT_ACK:
			cfg.tcp_th_flags |= TH_ACK;
			break;
		case OPT_URG:
			cfg.tcp_th_flags |= TH_URG;
			break;
		case OPT_XMAS:
			cfg.tcp_th_flags |= TH_X;
			break;
		case OPT_YMAS:
			cfg.tcp_th_flags |= TH_Y;
			break;
		case OPT_FRAG:
			cfg.opt_fragment = TRUE;
			break;
		case OPT_MOREFRAG:
			cfg.opt_mf = TRUE;
			break;
		case OPT_DONTFRAG:
			cfg.opt_df = TRUE;
			break;
		case OPT_FRAGOFF:
			cfg.ip_frag_offset = opt_num("-g/--fragoff", ago_optarg, 0, 65535);
			break;
		case OPT_TCPOFF:
			cfg.src_thoff = opt_num("-O/--tcpoff", ago_optarg, 0, 15);
			break;
		case OPT_REL:
			cfg.opt_relid = TRUE;
			break;
		case OPT_DATA:
			cfg.data_size = opt_num("-d/--data", ago_optarg, 0, 65535);
			break;
		case OPT_RAWIP:
			cfg.opt_rawipmode = TRUE;
			break;
		case OPT_ICMP:
			cfg.opt_icmpmode = TRUE;
			break;
		case OPT_ICMP_TS:
			cfg.opt_icmpmode = TRUE;
			cfg.opt_icmptype = 13;
			break;
		case OPT_ICMP_ADDR:
			cfg.opt_icmpmode = TRUE;
			cfg.opt_icmptype = 17;
			break;
		case OPT_UDP:
			cfg.opt_udpmode = TRUE;
			break;
		case OPT_SCAN:
			cfg.opt_scanmode = TRUE;
			if (cfg.opt_scanports != NULL && cfg.opt_scanports[0] != '\0')
				free(cfg.opt_scanports);
			cfg.opt_scanports = strdup(ago_optarg);
			if (cfg.opt_scanports == NULL) {
				fprintf(stderr, "styxwire: out of memory\n");
				return HPING_PARSE_ERROR;
			}
			break;
		case OPT_LISTEN:
			cfg.opt_listenmode = TRUE;
			strlcpy(cfg.sign, ago_optarg, 1024);
			cfg.signlen = strlen(ago_optarg);
			break;
		case OPT_IPPROTO:
			cfg.raw_ip_protocol = opt_num("-H/--ipproto", ago_optarg, 0, 255);
			break;
		case OPT_ICMPTYPE:
			cfg.opt_icmpmode= TRUE;
			cfg.opt_icmptype = opt_num("-C/--icmptype", ago_optarg, 0, 255);
			break;
		case OPT_ICMPCODE:
			cfg.opt_icmpmode= TRUE;
			cfg.opt_icmpcode = opt_num("-K/--icmpcode", ago_optarg, 0, 255);
			break;
		case OPT_BIND:
			cfg.ctrlzbind = BIND_TTL;
			break;
		case OPT_UNBIND:
			cfg.ctrlzbind = BIND_NONE;
			break;
		case OPT_DEBUG:
			cfg.opt_debug = TRUE;
			break;
		case OPT_VERBOSE:
			cfg.opt_verbose = TRUE;
			break;
		case OPT_WINID:
			cfg.opt_winid_order = TRUE;
			break;
		case OPT_KEEP:
			cfg.opt_keepstill = TRUE;
			break;
		case OPT_FILE:
			cfg.opt_datafromfile = TRUE;
			strlcpy(cfg.datafilename, ago_optarg, 1024);
			break;
		case OPT_DUMP:
			cfg.opt_hexdump = TRUE;
			break;
		case OPT_PRINT:
			cfg.opt_contdump = TRUE;
			break;
		case OPT_SIGN:
			cfg.opt_sign = TRUE;
			strlcpy(cfg.sign, ago_optarg, 1024);
			cfg.signlen = strlen(ago_optarg);
			break;
		case OPT_SAFE:
			cfg.opt_safe = TRUE;
			break;
		case OPT_END:
			cfg.opt_end = TRUE;
			break;
		case OPT_TRACEROUTE:
			cfg.opt_traceroute = TRUE;
			break;
		case OPT_TOS:
			if (!strcmp(ago_optarg, "help")) {
				tos_help();
				return HPING_PARSE_DONE;
			}
			else
			{
				/* TOS is given as hex digits (see --tos help) */
				char *end;
				unsigned long tos_tmp;

				errno = 0;
				tos_tmp = strtoul(ago_optarg, &end, 16);
				if (*ago_optarg == '\0' || *ago_optarg == '-' ||
				    end == ago_optarg || *end != '\0' ||
				    errno == ERANGE || tos_tmp > 0xff) {
					fprintf(stderr, "styxwire: option -o/--tos: "
						"invalid value '%s' (expected two "
						"hex digits, try --tos help)\n",
						ago_optarg);
					return HPING_PARSE_ERROR;
				}
				cfg.ip_tos |= tos_tmp; /* OR tos */
			}
			break;
		case OPT_MTU:
			cfg.virtual_mtu = opt_num("-m/--mtu", ago_optarg, 1, 65535);
			cfg.opt_fragment = TRUE;
			break;
		case OPT_SEQNUM:
			cfg.opt_seqnum = TRUE;
			break;
		case OPT_BADCKSUM:
			cfg.opt_badcksum = TRUE;
			break;
		case OPT_SETSEQ:
			cfg.set_seqnum = TRUE;
			cfg.tcp_seqnum = opt_unum("-M/--setseq", ago_optarg, 4294967295UL);
			break;
		case OPT_SETACK:
			cfg.set_ack = TRUE;
			cfg.tcp_ack = opt_unum("-L/--setack", ago_optarg, 4294967295UL);
			break;
		case OPT_RROUTE:
			cfg.opt_rroute = TRUE;
			break;
		case OPT_ICMP_HELP:
			icmp_help();	/* ICMP options help */
			return HPING_PARSE_DONE;
		case OPT_ICMP_IPVER:
			cfg.icmp_ip_version = opt_num("--icmp-ipver", ago_optarg, 0, 15);
			break;
		case OPT_ICMP_IPHLEN:
			cfg.icmp_ip_ihl = opt_num("--icmp-iphlen", ago_optarg, 0, 15);
			break;
		case OPT_ICMP_IPLEN:
			cfg.icmp_ip_tot_len = opt_num("--icmp-iplen", ago_optarg, 0, 65535);
			break;
		case OPT_ICMP_IPID:
			cfg.icmp_ip_id = opt_num("--icmp-ipid", ago_optarg, 0, 65535);
			break;
		case OPT_ICMP_IPPROTO:
			cfg.icmp_ip_protocol = opt_num("--icmp-ipproto", ago_optarg, 0, 255);
			break;
		case OPT_ICMP_IPSRC:
			strlcpy (cfg.icmp_ip_srcip, ago_optarg, 1024);
			break;
		case OPT_ICMP_IPDST:
			strlcpy (cfg.icmp_ip_dstip, ago_optarg, 1024);
			break;
		case OPT_ICMP_GW:
			strlcpy (cfg.icmp_gwip, ago_optarg, 1024);
			break;
		case OPT_ICMP_SRCPORT:
			cfg.icmp_ip_srcport = opt_num("--icmp-srcport", ago_optarg, 0, 65535);
			break;
		case OPT_ICMP_DSTPORT:
			cfg.icmp_ip_dstport = opt_num("--icmp-dstport", ago_optarg, 0, 65535);
			break;
		case OPT_FORCE_ICMP:
			cfg.opt_force_icmp = TRUE;
			break;
		case OPT_ICMP_CKSUM:
			cfg.icmp_cksum = opt_num("--icmp-cksum", ago_optarg, -1, 65535);
			break;
		case OPT_TCPEXITCODE:
			cfg.opt_tcpexitcode = TRUE;
			break;
		case OPT_FAST:
			delay_changed = 1;
			cfg.opt_waitinusec = TRUE;
			cfg.usec_delay.it_value.tv_sec =
			cfg.usec_delay.it_interval.tv_sec = 0;
			cfg.usec_delay.it_value.tv_usec = 
			cfg.usec_delay.it_interval.tv_usec = 100000;
			break;
		case OPT_FASTER:
			delay_changed = 1;
			cfg.opt_waitinusec = TRUE;
			cfg.usec_delay.it_value.tv_sec =
			cfg.usec_delay.it_interval.tv_sec = 0;
			cfg.usec_delay.it_value.tv_usec = 
			cfg.usec_delay.it_interval.tv_usec = 1;
			break;
		case OPT_TR_KEEP_TTL:
			cfg.opt_tr_keep_ttl = TRUE;
			break;
		case OPT_TCP_TIMESTAMP:
			cfg.opt_tcp_timestamp = TRUE;
			break;
		case OPT_TR_STOP:
			cfg.opt_tr_stop = TRUE;
			break;
		case OPT_TR_NO_RTT:
			cfg.opt_tr_no_rtt = TRUE;
			break;
		case OPT_RAND_DEST:
			cfg.opt_rand_dest = TRUE;
			break;
		case OPT_RAND_SOURCE:
			cfg.opt_rand_source = TRUE;
			break;
		case OPT_LSRR:
			cfg.opt_lsrr = TRUE;
			if (parse_route(cfg.lsr, &cfg.lsr_length, ago_optarg) == -1)
				return HPING_PARSE_ERROR;
			if (cfg.lsr[0])
				printf("Warning: erasing previously given "
						"loose source route");
			cfg.lsr[0] = 131;
			break;
		case OPT_SSRR:
			cfg.opt_ssrr = TRUE;
			if (parse_route(cfg.ssr, &cfg.ssr_length, ago_optarg) == -1)
				return HPING_PARSE_ERROR;
			if (cfg.ssr[0])
				printf("Warning: erasing previously given "
						"strong source route");
			cfg.ssr[0] = 137;
			break;
		case OPT_ROUTE_HELP:
			route_help();
			return HPING_PARSE_DONE;
		case OPT_APD_SEND:
			/* deferred to main(): nothing is sent while parsing */
			free(cfg.apd_send);
			cfg.apd_send = strdup(ago_optarg);
			if (cfg.apd_send == NULL) {
				fprintf(stderr, "styxwire: out of memory\n");
				return HPING_PARSE_ERROR;
			}
			break;
		case OPT_BEEP:
			cfg.opt_beep = TRUE;
			break;
		case OPT_FLOOD:
			cfg.opt_flood = TRUE;
			break;
		case OPT_DRY_RUN:
			cfg.opt_dry_run = TRUE;
			break;
		case OPT_JSON:
			cfg.opt_json = TRUE;
			break;
		case OPT_READ:
			free(cfg.readfile);
			cfg.readfile = strdup(ago_optarg);
			if (cfg.readfile == NULL) {
				fprintf(stderr, "styxwire: out of memory\n");
				return HPING_PARSE_ERROR;
			}
			break;
                case OPT_CLOCK_SKEW:
			cfg.opt_tcp_timestamp = TRUE;
                        cfg.opt_clock_skew = TRUE;
                        break;
                case OPT_CS_WINDOW:
                        cfg.cs_window = opt_num("--clock-skew-win", ago_optarg, 30, INT_MAX);
                        if (cfg.cs_window < 30) {
                            fprintf(stderr,
                                    "clock skew window can't be < 30 sec.\n");
                            return HPING_PARSE_ERROR;
                        }
                        break;
                case OPT_CS_WINDOW_SHIFT:
                        cfg.cs_window_shift = opt_num("--clock-skew-win-shift", ago_optarg, 1, INT_MAX);
                        if (cfg.cs_window_shift < 1) {
                            fprintf(stderr,
                                    "clock skew window shift can't be < 1\n");
                            return HPING_PARSE_ERROR;
                        }
                        break;
                case OPT_CS_VECTOR_LEN:
                        cfg.cs_vector_len = opt_num("--clock-skew-packets-per-sample", ago_optarg, 1, INT_MAX);
                        if (cfg.cs_vector_len < 1) {
                            fprintf(stderr,
                                    "clock skew packets per sample can't be < 1\n");
                            return HPING_PARSE_ERROR;
                        }
                        break;
		}
		if (parse_failed)
			return HPING_PARSE_ERROR;
	}

	/* missing target host? */
	if (targethost_set == 0 && cfg.opt_listenmode && cfg.opt_safe)
	{
		fprintf(stderr,
		"you must specify a target host if you require safe protocol\n"
		"because styxwire needs a target for HCMP packets\n");
		return HPING_PARSE_ERROR;
	}

	if (targethost_set == 0 && !cfg.opt_listenmode && cfg.apd_send == NULL) {
		fprintf(stderr, "styxwire: missing host argument\n"
			"Try `styxwire --help' for more information.\n");
		return HPING_PARSE_ERROR;
	}

	if (cfg.opt_numeric == TRUE) cfg.opt_gethost = FALSE;

	/* some error condition */
	if (cfg.data_size+IPHDR_SIZE+TCPHDR_SIZE > 65535) {
		fprintf(stderr, "Option error: sorry, data size must be <= %lu\n",
			(unsigned long)(65535-IPHDR_SIZE+TCPHDR_SIZE));
		return HPING_PARSE_ERROR;
	}
	else if (cfg.count <= 0 && cfg.count != -1) {
		fprintf(stderr, "Option error: count must > 0\n");
		return HPING_PARSE_ERROR;
	}
	else if (cfg.sending_wait < 0) {
		fprintf(stderr, "Option error: bad timing interval\n");
		return HPING_PARSE_ERROR;
	}
	else if (cfg.opt_waitinusec == TRUE && cfg.usec_delay.it_value.tv_usec < 0)
	{
		fprintf(stderr, "Option error: bad timing interval\n");
		return HPING_PARSE_ERROR;
	}
	else if (cfg.opt_datafromfile == TRUE && cfg.data_size == 0)
	{
		fprintf(stderr, "Option error: -E option useless without -d\n");
		return HPING_PARSE_ERROR;
	}
	else if (cfg.opt_sign && cfg.data_size && cfg.signlen > cfg.data_size)
	{
		fprintf(stderr, 
	"Option error: signature (%d bytes) is larger than data size\n"
	"check -d option, don't specify -d to let styxwire compute it\n", cfg.signlen);
		return HPING_PARSE_ERROR;
	}
	else if ((cfg.opt_sign || cfg.opt_listenmode) && cfg.signlen > 1024)
	{
		fprintf(stderr, "Option error: signature too big\n");
		return HPING_PARSE_ERROR;
	}
	else if (cfg.opt_safe == TRUE && cfg.src_id != -1)
	{
		fprintf(stderr, "Option error: sorry, you can't set id and "
				"use safe protocol at some time\n");
		return HPING_PARSE_ERROR;
	}
	else if (cfg.opt_safe == TRUE && cfg.opt_datafromfile == FALSE &&
			cfg.opt_listenmode == FALSE)
	{
		fprintf(stderr, "Option error: sorry, safe protocol is useless "
				"without 'data from file' option\n");
		return HPING_PARSE_ERROR;
	}
	else if (cfg.opt_safe == TRUE && cfg.opt_sign == FALSE &&
			cfg.opt_listenmode == FALSE)
	{
		fprintf(stderr, "Option error: sorry, safe protocol require you "
				"sign your packets, see --sign | -e option\n");
		return HPING_PARSE_ERROR;
	} else if (cfg.opt_rand_dest == TRUE && cfg.ifname[0] == '\0') {
		fprintf(stderr, "Option error: you need to specify an interface "
			"when the --rand-dest option is enabled\n");
		return HPING_PARSE_ERROR;
	}

	/* dependences */
	if (cfg.opt_safe == TRUE)
		cfg.src_id = 1;

	if (cfg.opt_traceroute == TRUE && cfg.ctrlzbind == BIND_DPORT)
		cfg.ctrlzbind = BIND_TTL;

	if (cfg.opt_traceroute == TRUE && src_ttl_set == 0)
		cfg.src_ttl = DEFAULT_TRACEROUTE_TTL;

	/* set the data size to the signature len if the no data size
	 * was specified */
	if (cfg.opt_sign && !cfg.data_size)
		cfg.data_size = cfg.signlen;

	/* If scan mode is on, and the -i option was not used,
	 * set the default delay to zero, that's send packets
	 * as fast as possible. */
	if (cfg.opt_scanmode && !delay_changed) {
		cfg.opt_waitinusec = TRUE;
		cfg.usec_delay.it_value.tv_sec =
		cfg.usec_delay.it_interval.tv_sec = 0;
		cfg.usec_delay.it_value.tv_usec = 
		cfg.usec_delay.it_interval.tv_usec = 0;
	}

	/* what the senders cannot handle is rejected here, before any
	 * socket is opened */
	if (cfg.opt_icmpmode && !cfg.opt_force_icmp &&
	    !icmp_type_supported(cfg.opt_icmptype)) {
		fprintf(stderr, "Option error: unsupported ICMP type %d "
			"(use --force-icmp to send it anyway)\n", cfg.opt_icmptype);
		return HPING_PARSE_ERROR;
	}
	if (cfg.opt_rand_dest) {
		unsigned char ra[4];
		if (parse_rand_dest(cfg.targetname, ra) == -1) {
			fprintf(stderr, "Option error: wrong --rand-dest target host, "
				"correct examples:\n  x.x.x.x, 192.168.x.x, 128.x.x.255\n"
				"you typed: %s\n", cfg.targetname);
			return HPING_PARSE_ERROR;
		}
	}

	return HPING_PARSE_OK;
}
