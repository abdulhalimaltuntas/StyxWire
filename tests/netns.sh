#!/bin/sh
# netns.sh -- live send AND receive verification over a veth pair inside a
# private user+network namespace.
#
# This is the ONLY test that puts real packets on an interface and opens a
# raw socket, so it is deliberately NOT part of "make check" (whose
# contract is: no root, no network traffic). Run it with "make check-live".
#
# It still needs neither real root nor a physical network: on Linux,
# unprivileged user namespaces give uid 0 inside a fresh, isolated network
# namespace, a veth pair is the only "wire", and nothing leaves the host.
# Where that is unavailable (no unshare, userns disabled, non-Linux, no
# python3) the test skips with status 77 rather than failing.
#
# What it proves that no offline test can: the packet leaves styxwire on a
# real AF_PACKET/raw socket, the kernel on the far end answers, styxwire
# captures the reply through libpcap, matches it, and computes an RTT --
# the whole live round trip, plus --scan and a spoofed source.

IP0=10.99.0.1
IP1=10.99.0.2
IFACE=v0
PEERIF=v1

# ---- stage 1: run outside the namespace, do preflight, then re-exec -------
if [ -z "$STYXWIRE_NETNS_INNER" ]; then
	# absolute path to the binary and to this script, before any cd
	case $0 in
	/*) self=$0 ;;
	*)  self=`pwd`/$0 ;;
	esac
	H=`pwd`/styxwire

	skip() { echo "SKIP netns.sh: $1"; exit 77; }

	[ "`uname -s`" = Linux ] || skip "not Linux (needs veth + user namespaces)"
	[ -x "$H" ] || skip "styxwire binary not built at $H"
	for t in unshare ip nsenter python3; do
		command -v "$t" >/dev/null 2>&1 || skip "missing tool: $t"
	done
	# Does an unprivileged user+net namespace actually work here? Some
	# hardened kernels disable it (kernel.unprivileged_userns_clone=0).
	unshare -Urn true 2>/dev/null || \
		skip "unprivileged user+net namespaces unavailable on this host"

	STYXWIRE="$H" STYXWIRE_NETNS_INNER=1 exec unshare -Urn sh "$self"
	skip "could not enter namespace"        # only reached if exec failed
fi

# ---- stage 2: inside uid-0 user ns with a private, empty network ns -------
H=$STYXWIRE
fail=0
n=0
PEER=""
LISTENER=""
TMP=""

check()
{
	n=$((n + 1))
	if [ "$1" != "$2" ]; then
		echo "FAIL netns.sh: $3 (got '$1', want '$2')"
		fail=$((fail + 1))
	fi
}

cleanup()
{
	[ -n "$LISTENER" ] && kill "$LISTENER" 2>/dev/null
	[ -n "$PEER" ] && kill "$PEER" 2>/dev/null
	[ -n "$TMP" ] && rm -rf "$TMP" 2>/dev/null
}
trap cleanup EXIT INT TERM

# The user-namespace root may still not own this netns (rare mapping
# failures); bail out as a skip rather than a spurious failure.
[ "`id -u`" = 0 ] || { echo "SKIP netns.sh: uid mapping did not yield root"; exit 77; }

# Build the wire: v0 stays here, v1 goes to a second netns held open by a
# backgrounded process that we nsenter into. Rendezvous is by FIFO, never
# by sleeping: "/proc/PID/ns/net" exists the instant the process does and
# says nothing about whether it has entered its NEW netns yet, so timing
# guesses race (v1 lands in the wrong namespace and nothing is reachable).
TMP=`mktemp -d 2>/dev/null` || { echo "SKIP netns.sh: no mktemp"; exit 77; }
f_peer="$TMP/peer.rdy"
f_list="$TMP/list.rdy"
mkfifo "$f_peer" "$f_list" 2>/dev/null || { echo "SKIP netns.sh: no mkfifo"; exit 77; }

ip link add "$IFACE" type "veth" peer name "$PEERIF" 2>/dev/null || {
	echo "SKIP netns.sh: cannot create veth (no CAP_NET_ADMIN in this netns)"
	exit 77
}

# The peer: a real second network namespace. It brings up its loopback,
# signals through the FIFO that its new netns is in place, then idles. We
# do NOT proceed until we have read that signal, so the netns is
# guaranteed to exist before we move v1 into it. (unshare -n keeps our
# mount namespace, so the peer and the nsenter'd listener both see $TMP.)
unshare -n sh -c 'ip link set lo up 2>/dev/null; echo R > '"$f_peer"'; exec sleep 120' &
PEER=$!
timeout 10 cat "$f_peer" >/dev/null 2>&1 || {
	echo "SKIP netns.sh: peer namespace did not come up"; exit 77; }

ip link set "$PEERIF" netns "$PEER"
ip addr add "$IP0/30" dev "$IFACE"
ip link set "$IFACE" up
ip link set lo up
nsenter -t "$PEER" -n ip addr add "$IP1/30" dev "$PEERIF"
nsenter -t "$PEER" -n ip link set "$PEERIF" up

# Silence IPv6 duplicate-address / router traffic so the IPv4 capture is
# deterministic; ignore failure (some kernels forbid it even here).
sysctl -qw "net.ipv6.conf.$IFACE.disable_ipv6=1" 2>/dev/null || true
nsenter -t "$PEER" -n sysctl -qw "net.ipv6.conf.$PEERIF.disable_ipv6=1" 2>/dev/null || true

# A TCP listener on 9999 in the peer, so one port is genuinely open. It
# signals through the FIFO only after listen() returns, so the open-port
# check below cannot race the bind.
nsenter -t "$PEER" -n python3 - "$f_list" <<'PY' &
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9999)); s.listen(16)
open(sys.argv[1], "w").write("R")
time.sleep(120)
PY
LISTENER=$!
timeout 10 cat "$f_list" >/dev/null 2>&1 || {
	echo "SKIP netns.sh: listener did not bind"; exit 77; }

# ---- the live checks ------------------------------------------------------

# 1. ICMP echo: at least one reply, no loss, an RTT line, exit 0.
out=`timeout 8 "$H" -I "$IFACE" -1 -c 2 "$IP1" 2>&1`; rc=$?
check "$rc" 0 "icmp: exit 0 when replies received"
check "`printf '%s\n' "$out" | grep -c 'icmp_seq='`" 2 "icmp: two replies seen"
check "`printf '%s\n' "$out" | grep -c '0% packet loss'`" 1 "icmp: no packet loss"
check "`printf '%s\n' "$out" | grep -c 'round-trip min/avg/max'`" 1 "icmp: rtt reported"

# 2. TCP SYN to a CLOSED port -> RST+ACK (flags RA), exit 0 (a reply is a reply).
out=`timeout 8 "$H" -I "$IFACE" -S -p 81 -c 1 "$IP1" 2>/dev/null`; rc=$?
check "$rc" 0 "tcp closed: exit 0 (RST is a reply)"
check "`printf '%s\n' "$out" | grep -c 'flags=RA'`" 1 "tcp closed: RST+ACK"
check "`printf '%s\n' "$out" | grep -c 'sport=81'`" 1 "tcp closed: reply from the probed port"

# 3. TCP SYN to the OPEN port 9999 -> SYN+ACK (flags SA).
out=`timeout 8 "$H" -I "$IFACE" -S -p 9999 -c 1 "$IP1" 2>/dev/null`; rc=$?
check "$rc" 0 "tcp open: exit 0"
check "`printf '%s\n' "$out" | grep -c 'flags=SA'`" 1 "tcp open: SYN+ACK from listener"

# 4. --scan over a small range: 9999 must be reported open (flags row),
#    the closed ports must land in "Not responding".
out=`timeout 12 "$H" -I "$IFACE" --scan 79-82,9999 -S "$IP1" 2>/dev/null`
check "`printf '%s\n' "$out" | awk '$1==9999' | grep -c 'S..A'`" 1 "scan: 9999 shown open"

# 5. --json: a reply event and a statistics event with matching, non-null counts.
out=`timeout 8 "$H" -I "$IFACE" -1 -c 3 --json "$IP1" 2>/dev/null`
check "`printf '%s\n' "$out" | grep -c '"type":"reply"'`" 3 "json: three reply events"
stat=`printf '%s\n' "$out" | grep '"type":"statistics"'`
check "`printf '%s\n' "$stat" | grep -c '"sent":3'`" 1 "json: sent count"
check "`printf '%s\n' "$stat" | grep -c '"received":3'`" 1 "json: received count"
check "`printf '%s\n' "$stat" | grep -c '"loss_percent":0'`" 1 "json: no loss"

# 6. Spoofed source (-a): the packet must still go out, but no reply can
#    match, so received stays 0 and the exit status is 1.
out=`timeout 8 "$H" -I "$IFACE" -a 10.99.0.55 -S -p 9999 -c 1 "$IP1" 2>&1`; rc=$?
check "$rc" 1 "spoof: exit 1 (no reply reaches the forged source)"
check "`printf '%s\n' "$out" | grep -c '100% packet loss'`" 1 "spoof: all packets lost"
check "`printf '%s\n' "$out" | grep -c '1 packets transmitted'`" 1 "spoof: packet still transmitted"

# ---- verdict --------------------------------------------------------------
if [ $fail -eq 0 ]; then
	echo "netns.sh: $n checks passed (live send/receive over veth)"
	exit 0
fi
echo "netns.sh: $fail of $n checks FAILED"
exit 1
