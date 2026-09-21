#!/bin/sh
# install.sh -- staged installation check.
#
# Installs into a temporary DESTDIR (a path containing a space, on
# purpose), verifies the layout, runs the installed binary, installs a
# second time (must be idempotent), uninstalls, and checks that nothing
# was written outside the staging directory.

fail=0
n=0
check()
{
	n=$((n + 1))
	if ! eval "$1"; then
		echo "FAIL install.sh: $2"
		fail=$((fail + 1))
	fi
}

stage=`mktemp -d "${TMPDIR:-/tmp}/hping stage.XXXXXX"` || exit 1
before=`ls -la . docs lib tests 2>/dev/null | md5sum`

make -s install DESTDIR="$stage" >/dev/null 2>&1
check "[ \$? -eq 0 ]" "make install DESTDIR exits 0"
sbin=`make -s -f Makefile -p 2>/dev/null | sed -n 's/^sbindir = //p' | head -1`
man=`make -s -f Makefile -p 2>/dev/null | sed -n 's/^mandir = //p' | head -1`
check "[ -x \"$stage$sbin/styxwire\" ]" "styxwire installed in sbindir"
check "[ -L \"$stage$sbin/hping3\" ]" "hping3 compatibility symlink"
check "[ -L \"$stage$sbin/hping\" ]" "hping symlink"
check "[ -L \"$stage$sbin/hping2\" ]" "hping2 symlink"
check "[ \"\`readlink \"$stage$sbin/hping\"\`\" = styxwire ]" "hping symlink is relative"
check "[ -f \"$stage$man/man8/styxwire.8\" ]" "man page installed"
check "[ -L \"$stage$man/man8/hping3.8\" ]" "hping3.8 man symlink"
check "\"$stage$sbin/styxwire\" --version >/dev/null 2>&1" "installed binary runs (--version)"
check "\"$stage$sbin/hping3\" --version >/dev/null 2>&1" "hping3 symlink runs"
check "\"$stage$sbin/hping2\" --version >/dev/null 2>&1" "symlink runs"

# second install must succeed (ln -sf, no 'file exists' errors)
make -s install DESTDIR="$stage" >/dev/null 2>&1
check "[ \$? -eq 0 ]" "second make install is idempotent"

make -s uninstall DESTDIR="$stage" >/dev/null 2>&1
check "[ \$? -eq 0 ]" "make uninstall exits 0"
check "[ ! -e \"$stage$sbin/styxwire\" ]" "uninstall removed the binary"
check "[ ! -e \"$stage$sbin/hping3\" ]" "uninstall removed the symlinks"
check "[ ! -e \"$stage$man/man8/styxwire.8\" ]" "uninstall removed the man page"

after=`ls -la . docs lib tests 2>/dev/null | md5sum`
check "[ \"$before\" = \"$after\" ]" "source tree untouched by install/uninstall"
rm -rf "$stage"

if [ $fail -eq 0 ]; then
	echo "install.sh: $n checks passed"
	exit 0
fi
echo "install.sh: $fail of $n checks FAILED"
exit 1
