#!/bin/sh
# libars.sh -- build libars.a and link a program against it alone.
#
# The archive must carry every helper the ARS code needs (adbuf, hex,
# hstring, strlcpy); nothing from the hping3 objects may be linked. The
# Makefile target tests/libars_link does the link with the same flags as
# the rest of the build (so SANITIZE=1 works too).

rm -f tests/libars_link
if ! make -s tests/libars_link >libars_link.err 2>&1; then
	echo "FAIL libars.sh: linking against libars.a alone failed:"
	cat libars_link.err
	rm -f libars_link.err
	exit 1
fi
rm -f libars_link.err
if desc=`./tests/libars_link`; then
	echo "libars.sh: standalone link and round trip OK: $desc"
	exit 0
fi
echo "FAIL libars.sh: the standalone program failed"
exit 1
