#!/bin/sh
# linklayer.sh -- link-layer (DLT) handling checks for styxwire.
#
# The same IPv4/TCP reply is written into a pcap savefile once per
# link-layer type, each time behind that type's own link header, and
# read back with --read. A wrong header size shifts the IP header and
# the reply is not dissected, so a correct dissection proves the offset.
# Unsupported types must fail cleanly instead of guessing a size.
#
# Runs as any user, needs no network and no capture device. python3
# writes the fixtures; the whole file is skipped (77) without it.

H=./styxwire
fail=0
n=0

check()
{
	n=$((n + 1))
	if [ "$1" != "$2" ]; then
		echo "FAIL linklayer.sh: $3 (got '$1', want '$2')"
		fail=$((fail + 1))
	fi
}

command -v python3 >/dev/null || { echo "SKIP linklayer.sh: python3 missing"; exit 77; }

dir=`mktemp -d "${TMPDIR:-/tmp}/styx-dlt.XXXXXX"` || exit 1
trap 'rm -rf "$dir"' EXIT INT TERM

python3 - "$dir" <<'PY'
import struct, sys, os

def ck(b):
    if len(b) % 2: b += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

# the payload every fixture carries: SYN+ACK from 10.0.0.2:80
sa = bytes([10,0,0,2]); da = bytes([10,0,0,1])
ip = bytearray(20)
ip[0] = 0x45; ip[2:4] = struct.pack('!H', 40); ip[4:6] = struct.pack('!H', 0x1234)
ip[8] = 64; ip[9] = 6; ip[12:16] = sa; ip[16:20] = da
ip[10:12] = struct.pack('!H', ck(bytes(ip)))
tcp = bytearray(20)
tcp[0:2] = struct.pack('!H', 80); tcp[2:4] = struct.pack('!H', 5000)
tcp[12] = 0x50; tcp[13] = 0x12; tcp[14:16] = struct.pack('!H', 512)
tcp[16:18] = struct.pack('!H', ck(sa + da + b'\x00\x06' + struct.pack('!H', 20) + bytes(tcp)))
datagram = bytes(ip) + bytes(tcp)

mac = bytes([0x02,0,0,0,0,1]) + bytes([0x02,0,0,0,0,2])

# name -> (pcap linktype, link header bytes)
types = {
    'null':   (0,   struct.pack('=I', 2)),                       # BSD loopback, host order AF_INET
    'loop':   (108, struct.pack('!I', 2)),                       # OpenBSD loopback, network order
    'en10mb': (1,   mac + b'\x08\x00'),                          # Ethernet II
    'raw':    (101, b''),                                        # bare IP
    'sll':    (113, struct.pack('!HHH', 0, 1, 6) + bytes([0x02,0,0,0,0,2]) + b'\x00\x00' + b'\x08\x00'),
    'sll2':   (276, b'\x08\x00' + b'\x00\x00' + struct.pack('!I', 2) +
                    struct.pack('!HBB', 1, 0, 6) + bytes([0x02,0,0,0,0,2]) + b'\x00\x00'),
    # header length is not fixed for these: they must be refused
    'ieee80211':  (105, b'\x00' * 24),
    'radiotap':   (127, b'\x00' * 8),
}
for name, (lt, lhdr) in types.items():
    pkt = lhdr + datagram
    assert len(lhdr) in (0,4,14,16,20,24,8), name
    with open(os.path.join(sys.argv[1], name + '.pcap'), 'wb') as f:
        f.write(struct.pack('!IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, lt))
        f.write(struct.pack('!IIII', 0, 0, len(pkt), len(pkt)))
        f.write(pkt)
PY
[ $? -eq 0 ] || { echo "FAIL linklayer.sh: could not write the fixtures"; exit 1; }

# every supported type must yield exactly the same dissection
for t in null loop en10mb raw sll sll2; do
	out=`$H --read "$dir/$t.pcap" --json -S -p 80 -a 10.0.0.1 10.0.0.2 2>/dev/null`
	rc=$?
	check "$rc" 0 "$t: exit status"
	check "`printf '%s\n' "$out" | grep -c '"type":"reply"'`" 1 "$t: one reply dissected"
	check "`printf '%s\n' "$out" | grep '"type":"reply"' | grep -c '"flags":"SA"'`" 1 "$t: reply flags SA"
	check "`printf '%s\n' "$out" | grep '"type":"reply"' | grep -c '"ttl":64'`" 1 "$t: reply ttl (IP header at the right offset)"
	check "`printf '%s\n' "$out" | grep '"type":"reply"' | grep -c '"id":4660'`" 1 "$t: reply IP id 0x1234"
	check "`printf '%s\n' "$out" | grep '"type":"reply"' | grep -c '"sport":80'`" 1 "$t: reply source port"
done

# a type whose link header length is not fixed must be refused, naming it
for t in ieee80211 radiotap; do
	err=`$H --read "$dir/$t.pcap" -S -p 80 -a 10.0.0.1 10.0.0.2 2>&1 >/dev/null`
	check "$?" 1 "$t: unsupported type exits 1"
	check "`printf '%s\n' "$err" | grep -ci 'unsupported link layer type'`" 1 "$t: diagnostic says the type is unsupported"
	check "`printf '%s\n' "$err" | grep -c 'IEEE802_11'`" 1 "$t: diagnostic names the link layer type"
done

if [ $fail -eq 0 ]; then
	echo "linklayer.sh: $n checks passed"
	exit 0
fi
echo "linklayer.sh: $fail of $n checks failed"
exit 1
