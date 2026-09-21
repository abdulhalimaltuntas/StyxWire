#!/bin/sh
# run.sh -- run the offline hping3 test-suite.
#
# Usage: sh tests/run.sh test-binary...   (invoked by "make check")
#
# Every binary is run in turn, then the CLI, link-layer, staged-install
# and benchmark self-checks.
# Exit status 77 from a test means "skipped" (missing optional runtime).
# No root, no network traffic, no capture device is needed.

failed=0
passed=0
skipped=0

run_one()
{
	name=$1; shift
	if "$@"; then
		passed=$((passed + 1))
	else
		rc=$?
		if [ $rc -eq 77 ]; then
			echo "SKIP: $name"
			skipped=$((skipped + 1))
		else
			echo "FAIL: $name (exit $rc)"
			failed=$((failed + 1))
		fi
	fi
}

for t in "$@"; do
	run_one "$t" "./$t"
done
run_one "tests/cli.sh" sh tests/cli.sh
run_one "tests/linklayer.sh" sh tests/linklayer.sh
run_one "tests/install.sh" sh tests/install.sh
run_one "tests/libars.sh" sh tests/libars.sh
run_one "tests/rcfile.sh" sh tests/rcfile.sh
# the benchmark is not timed here, only checked for computing what it claims
run_one "tests/bench --selftest" ./tests/bench --selftest

echo "----------------------------------------"
echo "test-suite: $passed passed, $failed failed, $skipped skipped"
[ $failed -eq 0 ]
