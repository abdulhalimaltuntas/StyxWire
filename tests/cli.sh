#!/bin/sh
# cli.sh -- characterization tests for the hping3 command line.
#
# Only code paths that run before any socket is opened are exercised:
# --help, --version and option validation. Runs as any user, needs no
# network. Exit status 0 when every check passes.

H=./hping3
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
check "`echo "$out" | head -1`" "usage: hping host [options]" "--help first line"
check "`$H --help 2>&1 >/dev/null | wc -c | tr -d ' '`" 0 "--help writes nothing to stderr"
check "`$H -h | grep -c -- '--fast      alias for -i u100000'`" 1 "--fast help text matches the code"
check "`$H -h | grep -c -- '--faster    alias for -i u1 '`" 1 "--faster help text matches the code"
check "`$H -h | grep -c 'winsize (default 512)'`" 1 "-w default in help matches DEFAULT_SRCWINSIZE"

out=`$H --version 2>/dev/null`; rc=$?
check "$rc" 0 "--version exit status"
check "`echo "$out" | head -1 | cut -d' ' -f1-2`" "hping version" "--version output"
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
