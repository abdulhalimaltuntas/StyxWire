#!/bin/sh
# rcfile.sh -- the scripting startup file is under the caller's control.
#
# The historical mode sourced ~/.hpingrc unconditionally and swallowed
# errors. StyxWire honours STYXWIRE_NORC (source nothing) and STYXWIRE_RC
# (source that file), reports a startup-file error on stderr, and prefers
# ~/.styxwirerc over ~/.hpingrc. Needs the binary to be Tcl-capable; skips
# otherwise (exit 77).

H=./styxwire
if ! $H --version | grep -q "TCL scripting capable"; then
	echo "rcfile.sh: SKIP (no Tcl support)"
	exit 77
fi

fail=0; n=0
check() { n=$((n+1)); [ "$1" = "$2" ] || { echo "FAIL rcfile.sh: $3 (got '$1', want '$2')"; fail=$((fail+1)); }; }

home=`mktemp -d "${TMPDIR:-/tmp}/styxrc.XXXXXX"`
script=`mktemp "${TMPDIR:-/tmp}/styxrc-run.XXXXXX"`
echo 'puts RAN; exit 0' > "$script"

# a startup file that marks it ran
echo 'set ::rc_marker HPINGRC' > "$home/.hpingrc"

# default: ~/.hpingrc is sourced (legacy name still works)
out=`printf 'puts $::rc_marker\n' | HOME="$home" $H 2>/dev/null`
check "`echo "$out" | tail -1`" "HPINGRC" "~/.hpingrc is sourced by default"

# ~/.styxwirerc takes precedence over ~/.hpingrc
echo 'set ::rc_marker STYXWIRERC' > "$home/.styxwirerc"
out=`printf 'puts $::rc_marker\n' | HOME="$home" $H 2>/dev/null`
check "`echo "$out" | tail -1`" "STYXWIRERC" "~/.styxwirerc preferred over ~/.hpingrc"

# STYXWIRE_NORC disables it: the variable is unset -> Tcl error on read
out=`printf 'puts [info exists ::rc_marker]\n' | HOME="$home" STYXWIRE_NORC=1 $H 2>/dev/null`
check "`echo "$out" | tail -1`" "0" "STYXWIRE_NORC sources nothing"

# STYXWIRE_RC points at a specific file, ignoring HOME
echo 'set ::rc_marker EXPLICIT' > "$script.rc"
out=`printf 'puts $::rc_marker\n' | HOME="$home" STYXWIRE_RC="$script.rc" $H 2>/dev/null`
check "`echo "$out" | tail -1`" "EXPLICIT" "STYXWIRE_RC sources the named file"

# STYXWIRE_RC empty: no startup file
out=`printf 'puts [info exists ::rc_marker]\n' | HOME="$home" STYXWIRE_RC= $H 2>/dev/null`
check "`echo "$out" | tail -1`" "0" "empty STYXWIRE_RC sources nothing"

# a broken startup file is reported on stderr but is non-fatal
echo 'this is not valid tcl {' > "$home/.styxwirerc"
err=`printf 'puts alive\n' | HOME="$home" $H 2>&1 >/dev/null`
out=`printf 'puts alive\n' | HOME="$home" $H 2>/dev/null`
check "`echo "$err" | grep -c 'Error in startup file'`" "1" "a broken startup file is reported"
check "`echo "$out" | tail -1`" "alive" "a broken startup file is non-fatal"

# a missing startup file is silent
rm -f "$home/.styxwirerc" "$home/.hpingrc"
err=`printf 'puts alive\n' | HOME="$home" $H 2>&1 >/dev/null`
check "`echo "$err" | grep -c 'startup file'`" "0" "a missing startup file is silent"

rm -rf "$home" "$script" "$script.rc"
if [ $fail -eq 0 ]; then echo "rcfile.sh: $n checks passed"; exit 0; fi
echo "rcfile.sh: $fail of $n checks FAILED"; exit 1
