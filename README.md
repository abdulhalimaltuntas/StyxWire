# StyxWire

**StyxWire** is a command-line TCP/IP packet assembler and analyzer: it builds
custom packets from the command line, sends them, and reports what comes back —
the way `ping` does with ICMP, but for TCP, UDP, ICMP and raw IP, with control
over almost every header field. It also embeds a **Tcl** scripting engine and
the **APD** packet-description language for building and dissecting packets
programmatically.

It is the maintained continuation of **hping3** by Salvatore Sanfilippo
(antirez). The command line, exit codes, the Tcl API and the APD language are
kept compatible: the binary installs as `styxwire`, with `hping3`, `hping2` and
`hping` as symlinks, so existing scripts keep working.

> **Scope.** StyxWire is a network *testing and analysis* tool for use on
> systems and networks you are authorized to test — firewall/ACL validation,
> path-MTU discovery, TCP/IP stack auditing, teaching. Sending and capturing
> need root (raw sockets); building and dissecting do not.

## What it is used for

- Firewall and ACL testing
- Advanced port scanning (`--scan`)
- Network performance testing with arbitrary protocols, sizes, TOS and
  fragmentation
- Path-MTU discovery
- Traceroute over arbitrary protocols
- Remote OS fingerprinting and TCP/IP stack auditing
- Teaching and learning TCP/IP

## Highlights

- **One packet engine (ARS).** Building, dissecting and the command-line send
  path (TCP/UDP/ICMP) all go through the same engine, so a packet is described
  and checksummed in exactly one place.
- **Deliberately malformed packets are first-class.** `--badcksum`,
  `-O/--tcpoff`, arbitrary fragmentation and hand-set fields are preserved on
  purpose — that is what the tool is for.
- **Offline modes need no root.** `--dry-run` builds and prints packets,
  `--read file.pcap` dissects a savefile, and the offline Tcl commands
  (`styxwire build`/`describe`/`validate`) all run as an ordinary user.
- **Structured output.** `--json` emits newline-delimited JSON events
  (replies, ICMP errors, statistics) for pipelines and automation
  ([docs/JSON.txt](docs/JSON.txt)).
- **IPv6 offline support.** Building and dissecting IPv6/ICMPv6 with correct
  checksums ([docs/IPV6.txt](docs/IPV6.txt)); sending IPv4 only, by decision.
- **Real link-layer awareness.** The IP offset is taken from the capture's
  link type (Ethernet, Linux cooked v1/v2, raw, loopback, …); unknown-length
  types are refused rather than guessed ([docs/PLATFORMS.txt](docs/PLATFORMS.txt)).

## Requirements

- A unix-like OS — **Linux is the tested platform**
- A C compiler (GCC or Clang, C99+) and GNU make
- **libpcap** with headers
- **Tcl 8.6 or 9.0** with headers — optional but recommended (for scripting)
- Optional: Clang for the libFuzzer targets

## Quick start

```sh
./configure          # ./configure --help lists the options
make
make check           # offline test-suite: no root, no network traffic
sudo make install
```

Other useful targets:

```sh
make check-live      # live send/receive over a veth pair in a private
                     # namespace — no real root, no physical NIC (Linux)
make bench           # offline benchmark of the packet engine
make fuzz            # libFuzzer drivers (needs Clang)
make styxwire-static # a single statically linked binary (needs static libs)
make WERROR=1 ...    # treat warnings as errors (CI does this)
make SANITIZE=1 ...  # build with ASan/UBSan
```

`make install` also installs bash and zsh tab-completion. See
[INSTALL](INSTALL) for staged installs (`DESTDIR`), Tcl on/off, cross
compiling and the sanitizer/fuzzing builds.

## Repository layout

```
src/            C sources and headers (the packet engine + CLI)
tests/          offline test-suite (test_*.c) and shell tests (*.sh)
lib/            Tcl example scripts (*.htcl)
completion/     bash and zsh tab-completion
docs/           manual page, format references, design docs and reports
RFCs/           reference RFCs the code implements
img/            project images
configure       generates Makefile, byteorder.h and systype.h
Makefile.in     the build; configure prepends the resolved variables
```

## Usage examples

```sh
# TCP SYN to port 80, twice
styxwire -S -p 80 -c 2 example.net

# SYN scan of a port range
styxwire --scan 1-1024 -S example.net

# ICMP echo, like ping
styxwire -1 example.net

# Build a packet and print it without sending (no root)
styxwire --dry-run -S -p 80 -a 10.0.0.1 192.0.2.2

# Dissect a capture as an ordinary user, as JSON
styxwire --read capture.pcap --json
```

Sending and capturing require root (raw sockets) and send IPv4; the command
line is compatible with hping3's, so its options and recipes still apply.

## Scripting and the APD language

With Tcl support, StyxWire is also a scripting shell and library:

```sh
styxwire exec ScriptName.htcl [arguments]
```

The Tcl API is documented in [docs/API.txt](docs/API.txt) and the **APD**
packet-description language in [docs/APD.txt](docs/APD.txt). The offline
commands `styxwire build`, `describe` and `validate` operate on APD text and
need no privileges. Startup file: `~/.styxwirerc` (falling back to
`~/.hpingrc`); `STYXWIRE_NORC` disables it and `STYXWIRE_RC=path` selects one.

## Testing

The default suite is **offline by contract** — no root, no traffic, no capture
device:

```sh
make check
```

It links the real objects, crafts packets in memory or reads pcap savefiles it
writes itself, and drives the event loop with a fake clock. The send path is
pinned by byte-exact vectors, the parsers are fuzzed (`make fuzz`), and builds
run clean under `-Werror` and ASan/UBSan.

The one test that puts real packets on an interface is opt-in and still needs
no real root:

```sh
make check-live      # veth pair inside an unprivileged user+network namespace
```

See [docs/LIVE-TESTS.txt](docs/LIVE-TESTS.txt) for how that works and what it
does (and does not) cover.

## Documentation

| File | What it covers |
|------|----------------|
| [docs/styxwire.8](docs/styxwire.8) | the manual page |
| [docs/API.txt](docs/API.txt) | the Tcl API |
| [docs/APD.txt](docs/APD.txt) | the APD packet-description language |
| [docs/JSON.txt](docs/JSON.txt) | the `--json` NDJSON schema |
| [docs/IPV6.txt](docs/IPV6.txt) | what works for IPv6, and why sending is refused |
| [docs/PLATFORMS.txt](docs/PLATFORMS.txt) | OS and link-layer support matrix |
| [docs/LIVE-TESTS.txt](docs/LIVE-TESTS.txt) | the live veth/namespace test |
| [docs/BENCHMARK.txt](docs/BENCHMARK.txt) | the offline benchmark and method |
| [docs/KARAR-KAYITLARI.md](docs/KARAR-KAYITLARI.md) | design decision records (Turkish) |
| docs/ASAMA1..5-RAPORU.md | development reports (Turkish) |

## Credits and license

StyxWire builds on **hping3** by Salvatore Sanfilippo (antirez) and the
contributors listed in [AUTHORS](AUTHORS). The original hping site was
<http://www.hping.org>.

Licensed under the **GNU General Public License, version 2** — see
[COPYING](COPYING).
