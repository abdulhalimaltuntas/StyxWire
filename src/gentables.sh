#!/bin/sh
# Regenerate sbignum-tables.{c,h}. Dev tool, not part of the normal build;
# run it from anywhere -- it works in its own directory (src/).
cd "$(dirname "$0")" || exit 1

CC=${CC:=cc}
CCOPT="-Wall -W -O2"

$CC gentables.c -o gentables $CCOPT
./gentables > sbignum-tables.c
./gentables h > sbignum-tables.h
rm -f gentables
echo "sbignum-tables.{c,h} generated in $(pwd)"
