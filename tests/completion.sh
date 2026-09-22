#!/bin/sh
# completion.sh -- keep the shell completions honest.
#
# The bash and zsh completions carry a baked list of long options. This test
# fails if that list drifts from the binary's own option table
# (parseoptions.c:hping_optlist), in either direction, so a new --option can
# never be added to the tool without also appearing in tab-completion (and a
# removed one can never linger). It also syntax-checks the scripts.
# No root, no network. Exit 0 when every check passes, 77 to skip.
#
# LC_ALL=C: character ranges like [a-z0-9-] and sort order are locale
# dependent (e.g. tr_TR collation), so text processing is pinned to C.
LC_ALL=C; export LC_ALL

here=`dirname "$0"`
root="$here/.."
src="$root/src/parseoptions.c"
bash_c="$root/completion/styxwire.bash"
zsh_c="$root/completion/styxwire.zsh"
tmp=`mktemp -d 2>/dev/null` || { echo "SKIP completion.sh: no mktemp"; exit 77; }
trap 'rm -rf "$tmp"' EXIT INT TERM
fail=0
n=0

check_same() {	# check_same LABEL FILE_A FILE_B
	n=$((n + 1))
	if ! diff -u "$2" "$3" >"$tmp/d" 2>&1; then
		echo "FAIL completion.sh: $1"
		sed 's/^/  /' "$tmp/d"
		fail=$((fail + 1))
	fi
}

check_rc() {	# check_rc LABEL RC
	n=$((n + 1))
	if [ "$2" != 0 ]; then
		echo "FAIL completion.sh: $1 (rc=$2)"
		fail=$((fail + 1))
	fi
}

[ -f "$src" ] && [ -f "$bash_c" ] && [ -f "$zsh_c" ] || {
	echo "SKIP completion.sh: sources not found"; exit 77; }

# pull every --long token out of a file, one per line, sorted unique
extract() {	# extract FILE [ONLY_LINES_MATCHING]
	awk -v pat="$2" '
		pat != "" && $0 !~ pat { next }
		{ s = $0
		  while (match(s, /--[a-z0-9-]+/)) {
			print substr(s, RSTART, RLENGTH)
			s = substr(s, RSTART + RLENGTH) } }' "$1" | sort -u
}

# the authoritative set: long options from the binary's table
awk '/hping_optlist\[\]/{f=1} f&&/AGO_LIST_TERM/{exit}
	f { s=$0; if (match(s, /"[a-z0-9-]+"/)) {
		o = substr(s, RSTART+1, RLENGTH-2); if (o != "") print "--" o } }' \
	"$src" | sort -u > "$tmp/table"

extract "$bash_c" longopts > "$tmp/bash"
extract "$zsh_c"  longopts > "$tmp/zsh"

check_same "bash completion long options match the binary table" "$tmp/table" "$tmp/bash"
check_same "zsh completion long options match the binary table"  "$tmp/table" "$tmp/zsh"

# both scripts must parse
if command -v bash >/dev/null 2>&1; then
	bash -n "$bash_c" 2>/dev/null; check_rc "bash completion parses" "$?"
fi
if command -v zsh >/dev/null 2>&1; then
	zsh -n "$zsh_c" 2>/dev/null; check_rc "zsh completion parses" "$?"
fi

if [ $fail -eq 0 ]; then
	echo "completion.sh: $n checks passed"
	exit 0
fi
echo "completion.sh: $fail of $n checks FAILED"
exit 1
