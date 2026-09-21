#!/bin/sh
# cli.sh -- characterization tests for the styxwire command line.
#
# Only code paths that run before any socket is opened are exercised:
# --help, --version and option validation. Runs as any user, needs no
# network. Exit status 0 when every check passes.

H=./styxwire
fail=0
n=0

check()
{
	n=$((n + 1))
	if [ "$1" != "$2" ]; then
		echo "FAIL cli.sh: $3 (got '$1', want '$2')"
		fail=$((fail + 1))
	fi
}

# --help / --version: exit 0, output on stdout, nothing on stderr
out=`$H --help 2>/dev/null`; rc=$?
check "$rc" 0 "--help exit status"
check "`echo "$out" | head -1`" "usage: styxwire host [options]" "--help first line"
check "`$H --help 2>&1 >/dev/null | wc -c | tr -d ' '`" 0 "--help writes nothing to stderr"
check "`$H -h | grep -c -- '--fast      alias for -i u100000'`" 1 "--fast help text matches the code"
check "`$H -h | grep -c -- '--faster    alias for -i u1 '`" 1 "--faster help text matches the code"
check "`$H -h | grep -c 'winsize (default 512)'`" 1 "-w default in help matches DEFAULT_SRCWINSIZE"

out=`$H --version 2>/dev/null`; rc=$?
check "$rc" 0 "--version exit status"
check "`echo "$out" | grep -c 'based on hping3 3.0.0-alpha-1'`" 1 "--version names the hping3 base"
check "`echo "$out" | head -1 | cut -d' ' -f1-2`" "StyxWire version" "--version output"
out=`$H -v`; check "$?" 0 "-v exit status"

# no arguments: the Tcl shell (exit 0 at EOF of stdin) when scripting is
# compiled in, otherwise a diagnostic and exit 1
if $H --version | grep -q "TCL scripting capable"; then
	out=`$H </dev/null 2>&1`; rc=$?
	check "$rc" 0 "no arguments: Tcl shell exits 0 at EOF"
else
	out=`$H </dev/null 2>&1`; rc=$?
	check "$rc" 1 "no arguments without Tcl: error"
	check "`echo "$out" | grep -c 'without TCL'`" 1 "no arguments without Tcl: message"
fi
out=`$H -S 2>&1`; rc=$?
check "$rc" 1 "no target host: usage error"
check "`echo "$out" | grep -c 'missing host argument'`" 1 "no target host: message"

# numeric validation (option value, expected range) -- exit 1 + message,
# no packet is sent because parsing fails before any socket is opened
bad()
{
	out=`$H $1 192.0.2.1 2>&1 >/dev/null`; rc=$?
	check "$rc" 1 "$1 rejected"
	check "`echo "$out" | grep -c "invalid value"`" 1 "$1 diagnostic"
}
bad "-c 0"
bad "-c -3"
bad "-c abc"
bad "-c 12x"
bad "-c ''"
bad "-t 256"
bad "-t -1"
bad "-p 65536"
bad "-p 80x"
bad "-s -1"
bad "-w 70000"
bad "-O 16"
bad "-N 65536"
bad "-d 65536"
bad "-H 256"
bad "-C 256"
bad "-K 300"
bad "-m 0"
bad "-m 65536"
bad "-i u-1"
bad "-i abc"
bad "-M 4294967296"
bad "-L -1"
bad "--icmp-ipver 16"
bad "--icmp-iphlen 16"
bad "--icmp-cksum -2"
bad "--icmp-srcport 65536"
bad "--clock-skew-win 29"
bad "--clock-skew-win-shift 0"
bad "--clock-skew-packets-per-sample 0"
out=`$H -o zz 192.0.2.1 2>&1 >/dev/null`; rc=$?
check "$rc" 1 "-o zz rejected"
check "`echo "$out" | grep -c 'tos'`" 1 "-o diagnostic"
out=`$H -o 100 192.0.2.1 2>&1 >/dev/null`; rc=$?
check "$rc" 1 "-o 100 (three hex digits) rejected"
out=`$H --scan 1- -S 192.0.2.1 2>&1 >/dev/null`; rc=$?
check "$rc" 1 "--scan 1- rejected"

# option combination errors that were already diagnosed
out=`$H -E /dev/null 192.0.2.1 2>&1`; rc=$?
check "$rc" 1 "-E without -d"
check "`echo "$out" | grep -c 'useless without -d'`" 1 "-E without -d message"
out=`$H --rand-dest x.x.x.x 2>&1`; rc=$?
check "$rc" 1 "--rand-dest without -I"

# --dry-run: builds and prints packets, sends nothing, needs no root.
# stdout carries the banner and the dry-run lines; extract the hex.
out=`$H --dry-run -c 2 -S -p 80 -a 10.0.0.1 10.0.0.2 2>/dev/null`; rc=$?
check "$rc" 0 "--dry-run exit status (no root)"
check "`echo "$out" | grep -c '^dry-run: to 10.0.0.2, 40 bytes: 4500'`" 2 "--dry-run prints two 40-byte IP datagrams"
hex=`echo "$out" | grep '^dry-run:' | head -1 | sed 's/.*: //'`
# TCP SYN from 10.0.0.1 to 10.0.0.2 port 80: proto 06 (IP byte 9 = hex 19-20),
# dport 0050 (TCP bytes 3-4 = hex 45-48), SYN flag 02 (TCP byte 13 = hex 65-66)
check "`echo "$hex" | cut -c19-20`" "06" "--dry-run built IP proto is TCP"
check "`echo "$hex" | cut -c45-48`" "0050" "--dry-run built TCP dport is 80"
check "`echo "$hex" | cut -c67-68`" "02" "--dry-run built TCP flag is SYN"
uhex=`$H --dry-run --udp -c 1 10.0.0.2 2>/dev/null | grep '^dry-run:' | head -1 | sed 's/.*: //'`
check "`echo "$uhex" | cut -c19-20`" "11" "--dry-run --udp built IP proto is UDP"
if command -v strace >/dev/null; then
	# no raw socket is opened (interface discovery still uses a UDP socket)
	check "`strace -f -qq -e trace=socket $H --dry-run -c 1 -S 10.0.0.2 2>&1 >/dev/null | grep -c 'SOCK_RAW'`" 0 "--dry-run opens no raw socket"
fi

# unknown / ambiguous options
out=`$H --no-such-option 192.0.2.1 2>&1`; rc=$?
check "$rc" 1 "unknown option"
check "`echo "$out" | grep -c 'unrecognized option'`" 1 "unknown option message"

if [ $fail -eq 0 ]; then
	echo "cli.sh: $n checks passed"
	exit 0
fi
echo "cli.sh: $fail of $n checks FAILED"
exit 1
