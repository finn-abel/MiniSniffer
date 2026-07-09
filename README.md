# MiniSniffer

MiniSniffer is a small C packet sniffer and network analyzer built on
libpcap. It captures live packets, parses common IPv4/IPv6 pcap link-layer
formats, applies simple filters, prints readable packet summaries, optionally
writes CSV logs, and can report capture statistics when the run completes.

## Documentation

- [Architecture](docs/architecture.md)
- [Contributing](CONTRIBUTING.md)
- [License](LICENSE)

## Features

- Live packet capture with libpcap
- Automatic default interface selection
- Explicit interface selection with `--interface`
- IPv4 and IPv6 packet parsing for TCP, UDP, ICMP/ICMPv6, and other protocols
- Conservative ARP summary metadata (operation, sender/target IP and MAC) for
  the common Ethernet/IPv4 case
- Conservative IPv6 extension-header handling before TCP/UDP/ICMPv6 parsing
- Bounded IPv4 fragment reassembly for transport and app decoding
- Protocol, port, and IPv4/IPv6 host filters
- Kernel-level BPF pre-filtering compiled from simple protocol/port/host
  filters, in both live and offline capture, with `--no-bpf` to disable it
- Bounded packet payload inspection
- Literal text and hex payload filters
- Packet-local HTTP, DNS, TLS ClientHello, DHCP, mDNS, and conservative QUIC
  Initial-packet metadata decoding
- Bounded TCP stream reassembly for HTTP, DNS-over-TCP, and TLS ClientHello metadata
- Application metadata filters
- CSV logging for displayed packets
- Summary statistics for displayed packets
- Clean Ctrl+C shutdown for unlimited captures
- Unit tests for the core modules
- Lightweight benchmark targets for the parser, app decoders, filters, and
  TCP reassembly
- libFuzzer-compatible fuzzing harnesses and a seed corpus for the parser,
  DNS, HTTP, TLS, app dispatch, TCP stream reassembly, and offline pcap
  ingestion

## Safety and Scope

MiniSniffer is for learning, local diagnostics, and authorized network
observation. It is not for MITM, credential capture, decryption, injection,
stealth, evasion, persistence, or use on networks you do not own or have
explicit permission to inspect.

The project focuses on bounded parsing, metadata extraction, filtering, CSV
logging, and statistics. It does not decrypt encrypted traffic and does not
modify or inject packets.

## Requirements

- C compiler with C11 support
- `make`
- libpcap

On macOS with Homebrew:

```sh
brew install libpcap pkg-config
```

On Debian or Ubuntu:

```sh
sudo apt-get install build-essential libpcap-dev pkg-config
```

On Fedora or RHEL:

```sh
sudo dnf install gcc make libpcap-devel pkgconf-pkg-config
```

On Arch Linux:

```sh
sudo pacman -S base-devel libpcap pkgconf
```

Packet capture usually requires elevated permissions. On macOS, run MiniSniffer
with `sudo` or configure BPF capture permissions for your account. On Linux,
run with `sudo` or grant the binary the `cap_net_raw`/`cap_net_admin`
capabilities instead of running as root, for example
`sudo setcap cap_net_raw,cap_net_admin+eip ./MiniSniffer`.

## Build

```sh
make
```

This creates the `MiniSniffer` executable in the project root.

The build uses `pkg-config --cflags --libs libpcap` when libpcap metadata is
available and falls back to `-lpcap` otherwise. Override `CC`, `CFLAGS`,
`PKG_CONFIG`, or `LDLIBS` on the `make` command line if your local toolchain
needs custom settings.

Build with optional libidn2 support to enable IDNA domain matching:

```sh
make WITH_LIBIDN2=1
```

This requires libidn2 headers and libraries to be installed locally.

Install or uninstall the executable with:

```sh
make install
make uninstall
```

Both targets honor `PREFIX`, which defaults to `/usr/local`, and `DESTDIR` for
staged installs. `make install` also installs the man page and bash/zsh/fish
completions (see [Man Page](#man-page) and [Shell Completions](#shell-completions)
below); each has its own directory variable
(`MANDIR`, `BASH_COMPLETION_DIR`, `ZSH_COMPLETION_DIR`, `FISH_COMPLETION_DIR`)
that can be overridden independently of `PREFIX` if your system expects a
different layout. `make uninstall` removes exactly the files `make install`
placed.

### Homebrew (macOS, build from source)

A Homebrew formula is kept in-tree at `packaging/homebrew/minisniffer.rb` for
future tap use; it is not yet published to homebrew-core or a hosted tap.
Install directly from the formula file in a local checkout:

```sh
brew install --build-from-source ./packaging/homebrew/minisniffer.rb
```

Or build from the repository's current default branch instead of a tagged
release:

```sh
brew install --HEAD ./packaging/homebrew/minisniffer.rb
```

The formula's stable `url`/`sha256` fields are placeholders until the first
tagged release is published through the [release workflow](#continuous-integration);
`--HEAD` works immediately since it builds directly from this git repository.
The formula installs the `MiniSniffer` binary, the man page, and all three
shell completions in one step.

## Quick Start

Capture five displayed packets on the automatically selected interface:

```sh
sudo ./MiniSniffer --count 5
```

Capture on a specific interface:

```sh
sudo ./MiniSniffer --interface en0 --count 5
```

Capture TCP packets and print stats at the end:

```sh
sudo ./MiniSniffer --protocol tcp --count 20 --stats
```

Write displayed packets to a CSV file:

```sh
sudo ./MiniSniffer --count 10 --log packets.csv
```

Inspect payload previews and filter for HTTP request bytes:

```sh
sudo ./MiniSniffer --protocol tcp --payload --payload-bytes 80 --payload-contains "GET "
```

## Usage

```text
Usage: ./MiniSniffer [--help] [--version] [--list-interfaces] [--interface <name>]
       [--count <number>] [--quiet] [--verbose] [--no-color]
       [--protocol <tcp|udp|icmp|arp|other>] [--port <number>]
       [--host <ip>] [--payload] [--payload-bytes <number>]
       [--payload-decode-bytes <number>] [--domain-match <mode>]
       [--payload-contains <text>] [--payload-hex <hex>] [--log <file>]
       [--read <file.pcap>] [--write <file.pcap>] [--no-bpf]
       [--json] [--flush-log <always|line|exit>]
       [--decode-app] [--reassemble] [--max-flows <number>]
       [--stream-buffer-bytes <number>] [--flow-timeout <seconds>]
       [--app <http|dns|tls|dhcp|mdns|quic>] [--http-host <host>]
       [--http-method <method>] [--dns-query <name>] [--dns-type <type>]
       [--tls-sni <host>] [--tls-alpn <protocol>]
       [--dhcp-type <type>] [--quic-version <version>] [--stats]
```

## Options

| Option | Description |
| --- | --- |
| `--help` | Print usage and exit. |
| `--version` | Print the MiniSniffer version and exit. |
| `--list-interfaces` | List libpcap capture devices with descriptions, address hints, and default-candidate markers. |
| `--interface <name>` | Capture from a specific interface, such as `en0`. |
| `--count <number>` | Stop after this many displayed packets. If omitted, capture continues until Ctrl+C. |
| `--quiet` | Suppress startup and stop summaries. Packet output and errors still print. |
| `--verbose` | Print the full startup configuration summary before capture. |
| `--no-color` | Disable terminal color output. Current MiniSniffer output is plain text. |
| `--protocol <tcp|udp|icmp|arp|other>` | Display only packets matching the selected protocol. |
| `--port <number>` | Display only TCP/UDP packets where the source or destination port matches. |
| `--host <ip>` | Display only packets where the source or destination IPv4 or IPv6 address matches. |
| `--payload` | Print a bounded hex and ASCII payload preview for displayed packets. |
| `--payload-bytes <number>` | Set the payload preview length. Default is 256 bytes. Maximum is 256 bytes. |
| `--payload-decode-bytes <number>` | Set the payload decode window used by payload filters and packet-local app decoders. Default is 2048 bytes. Maximum is 65535 bytes. |
| `--payload-contains <text>` | Display only packets whose bounded payload decode window contains the literal text. |
| `--payload-hex <hex>` | Display only packets whose bounded payload decode window contains the byte pattern. |
| `--read <file.pcap>` | Read packets from an offline pcap file instead of live capture. Does not require interface selection or capture permissions. |
| `--write <file.pcap>` | Write displayed packets to a new pcap file, preserving timestamps and link type. Existing files are refused. |
| `--no-bpf` | Disable kernel-level BPF pre-filtering and rely entirely on software filtering. Useful for debugging filter behavior. |
| `--json` | Print displayed packets as JSON Lines instead of human-readable packet text. |
| `--decode-app` | Decode packet-local HTTP, DNS, and TLS ClientHello metadata. |
| `--reassemble` | Enable bounded TCP stream reassembly for app decoding. Requires `--decode-app`. |
| `--max-flows <number>` | Set the maximum number of tracked TCP flows for reassembly. Default is 512; maximum is 1024. Requires `--reassemble`. |
| `--stream-buffer-bytes <number>` | Set the per-direction TCP stream buffer cap. Default is 32768 bytes; maximum is 1048576 bytes. Requires `--reassemble`. |
| `--flow-timeout <seconds>` | Evict flows idle for at least this many seconds. Default is 60 seconds. Requires `--reassemble`. |
| `--app <http|dns|tls|dhcp|mdns|quic>` | Display only packets with decoded app metadata for the selected protocol. Requires `--decode-app`. |
| `--http-host <host>` | Display only decoded HTTP packets with a matching Host header. Requires `--decode-app`. |
| `--http-method <method>` | Display only decoded HTTP requests with a matching method. Requires `--decode-app`. |
| `--dns-query <name>` | Display only decoded DNS or mDNS packets with a matching first query name. Requires `--decode-app`. |
| `--dns-type <type>` | Display only decoded DNS or mDNS packets with a matching first query type, such as `A` or `AAAA`. Requires `--decode-app`. |
| `--tls-sni <host>` | Display only decoded TLS ClientHello packets with a matching SNI hostname. Requires `--decode-app`. |
| `--tls-alpn <protocol>` | Display only decoded TLS ClientHello packets advertising the ALPN protocol. Requires `--decode-app`. |
| `--dhcp-type <type>` | Display only decoded DHCP packets with a matching message type, such as `discover`, `offer`, `request`, or `ack`. Requires `--decode-app`. |
| `--quic-version <version>` | Display only decoded QUIC Initial packets with a matching version, decimal or `0x`-prefixed hex. Requires `--decode-app`. |
| `--domain-match <normalized|exact|idna>` | Set HTTP Host, DNS query, and TLS SNI domain matching mode. Default is `normalized`. `idna` requires `WITH_LIBIDN2=1`. |
| `--log <file>` | Write displayed packets to a CSV file. |
| `--flush-log <always|line|exit>` | Control CSV flush timing. Default is `line`, preserving the current row-by-row safe behavior. |
| `--stats` | Print displayed packet totals after capture completes. |

`--count` is applied after filtering. For example, `--protocol tcp --count 10`
stops after ten displayed TCP packets, not after ten raw packets.

## Interface Selection

When `--interface` is omitted, MiniSniffer enumerates libpcap devices and
chooses a practical default. On macOS it prefers normal non-loopback IPv4
interfaces such as `en0` and avoids common internal or tunnel interfaces such
as `ap*`, `awdl*`, `llw*`, and `utun*`.

List the interfaces MiniSniffer can see:

```sh
./MiniSniffer --list-interfaces
```

The `*` marker indicates a default candidate. Hints include `loopback`,
`internal`, `ipv4`, and `ipv6` when MiniSniffer can infer them from libpcap
metadata.

If automatic selection does not choose the interface you want, pass the
interface explicitly:

```sh
sudo ./MiniSniffer --interface en0 --count 5
```

## Filters

Filters use AND logic. When multiple filters are enabled, every enabled filter
must match before a packet is printed, logged, counted, or included in stats.

Examples:

```sh
sudo ./MiniSniffer --protocol tcp --count 10
sudo ./MiniSniffer --protocol udp --count 10
sudo ./MiniSniffer --protocol icmp --count 5
sudo ./MiniSniffer --port 443 --count 10
sudo ./MiniSniffer --protocol tcp --port 443 --count 10
sudo ./MiniSniffer --host 8.8.8.8 --count 10
sudo ./MiniSniffer --host 2001:4860:4860::8888 --count 10
sudo ./MiniSniffer --protocol tcp --port 443 --host 142.250.190.14 --count 10
sudo ./MiniSniffer --protocol udp --port 53 --host 2001:4860:4860::8888 --decode-app --app dns
```

Port filters apply only to packets with TCP or UDP ports. ICMP and other
packets do not match a port filter.

### BPF Pre-Filtering

When `--protocol`, `--port`, or `--host` are enabled, MiniSniffer compiles a
matching libpcap BPF expression and installs it with `pcap_setfilter`, in both
live and offline (`--read`) capture. This is a pure optimization: it reduces
how many packets libpcap delivers to MiniSniffer at all, but every displayed
packet is still fully re-checked by the exact same software filters described
above. Only filters that translate exactly to kernel-level primitives are
ever compiled into BPF:

- `--protocol tcp` -> `tcp`
- `--protocol udp` -> `udp`
- `--protocol icmp` -> `(icmp or icmp6)`
- `--protocol arp` -> `arp`
- `--protocol other` has no safe BPF equivalent and contributes no clause;
  `--port`/`--host` still narrow the BPF filter even when protocol cannot
- `--port <number>` -> `port <number>`
- `--host <ip>` -> `host <ip>`

Payload and application-layer filters (`--payload-contains`, `--payload-hex`,
`--app`, and all app-specific filters) can never be expressed safely in BPF,
since they require inspecting content BPF cannot see. They always run
entirely in software, regardless of BPF pre-filtering.

If BPF compilation or installation fails for any reason (unsupported
expression on a given link type, driver quirk, and so on), MiniSniffer prints
a warning and falls back to inspecting every packet in software; this never
aborts capture; correctness never depends on BPF succeeding. Use `--no-bpf` to
disable BPF pre-filtering entirely, which is useful when debugging whether an
issue is related to the kernel-level filter.

```sh
sudo ./MiniSniffer --protocol tcp --port 443 --host 142.250.190.14 --verbose --count 10
sudo ./MiniSniffer --protocol tcp --port 443 --no-bpf --count 10
```

With `--verbose`, a successfully installed filter prints
`BPF filter installed: <expression>` before capture begins.

Payload filters inspect the bounded payload decode window, not the smaller
console/log preview. They do not require `--payload`; use `--payload` only when
you also want to print or log previews. Use `--payload-decode-bytes` to tune
the decode and filter window separately from `--payload-bytes`.

Text payload filter:

```sh
sudo ./MiniSniffer --protocol tcp --payload-contains "Host:"
```

Hex payload filter:

```sh
sudo ./MiniSniffer --payload-hex "47 45 54 20"
```

Hex patterns may include spaces, colons, or hyphens as separators. The example
above matches the bytes for `GET `.

Application filters use decoded packet-local metadata when `--reassemble` is
off. If app metadata is absent or incomplete, app filters fail for that packet.
With `--reassemble`, app filters use flow classification instead: packets before
classification do not match, and future packets in a matching classified flow
pass. MiniSniffer does not buffer or replay earlier packets after a flow becomes
classified.

HTTP Host, DNS query, and TLS SNI filters use normalized domain matching by
default: ASCII case-insensitive comparison with one trailing root dot ignored on
either side. Use `--domain-match exact` for byte-for-byte matching. Builds made
with `make WITH_LIBIDN2=1` also accept `--domain-match idna`, which converts
IDNA names through libidn2 before applying normalized matching.

Application filter examples:

```sh
sudo ./MiniSniffer --decode-app --app http --http-host example.com
sudo ./MiniSniffer --decode-app --app dns --dns-query example.com --dns-type A
sudo ./MiniSniffer --decode-app --app tls --tls-sni example.com --tls-alpn h2
sudo ./MiniSniffer --decode-app --reassemble --app tls --tls-sni example.com --count 5
sudo ./MiniSniffer --decode-app --app mdns --dns-query printer.local
sudo ./MiniSniffer --decode-app --app dhcp --dhcp-type discover
sudo ./MiniSniffer --decode-app --app quic --quic-version 0x00000001
sudo ./MiniSniffer --protocol arp --count 10
```

## Output

MiniSniffer prints one line for each displayed packet. TCP and UDP packets
include ports:

```text
[001] TCP  192.168.1.25:51432 -> 142.250.190.14:443 size=54
```

Packets without ports omit them:

```text
[002] ICMP 192.168.1.25 -> 8.8.8.8 size=98
```

ICMPv6 packets are still matched by `--protocol icmp`; text output includes
the ICMPv6 type and code when the common header is captured:

```text
[005] ICMPv6 2001:db8::1 -> 2001:db8::2 size=62 type=128 code=0
```

ARP packets show the operation and sender/target MAC addresses; sender and
target IPv4 addresses are shown as the usual source and destination fields:

```text
[006] ARP   192.168.1.10 -> 192.168.1.1 size=42 op=request sender_mac=00:11:22:33:44:55 target_mac=00:00:00:00:00:00
```

With `--payload`, MiniSniffer prints a bounded payload preview below each
displayed packet:

```text
[003] TCP  192.168.1.25:51432 -> 142.250.190.14:80 size=71
      payload length=17 preview=17
      hex: 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a 0d
      ascii: GET / HTTP/1.1...
```

With `--decode-app`, decoded application metadata is printed below the packet
summary. The status is one of `no_match`, `need_more`, `malformed`,
`truncated`, or `decoded`:

```text
[004] TCP  192.168.1.25:51432 -> 93.184.216.34:80 size=512
      app: status=decoded protocol=http method=GET host=example.com path=/
```

With `--decode-app --reassemble`, stream-derived app metadata is printed as a
flow event with the first packet from that flow that passes all active filters:

```text
flow tcp 192.168.1.25:51432 <-> 93.184.216.34:443 app=tls sni=example.com alpn=h2
```

Supported pcap link-layer formats include Ethernet, raw IPv4/IPv6, Linux cooked
capture v1/v2, and BSD null/loopback. Packets whose link or network layer cannot
be decoded are displayed as `OTHER` when they pass active filters. Capture
startup rejects unsupported libpcap data-link types with a clear error rather
than interpreting an unknown frame format incorrectly.

Application metadata is escaped before terminal output. Control bytes are
shown as `\xNN` text and cannot emit terminal control sequences.

Use `--json` to print displayed packets as JSON Lines:

```sh
sudo ./MiniSniffer --json --decode-app --payload --count 5
```

Each displayed packet is one JSON object with `timestamp`, `packet_number`,
`transport`, `packet_length`, optional `payload`, `app`, `app_decode_status`,
and `app_source`. `transport` is itself an object with `protocol`, and
`src_ip`/`dst_ip` when addresses are available; `src_port`/`dst_port` are
present only for TCP/UDP packets, and `icmp_type`/`icmp_code` only for
ICMP/ICMPv6 packets. Payload previews include bounded `length`,
`preview_length`, `truncated`, `hex`, and `ascii` fields when `--payload` is
enabled and the packet has payload; `app` is `null` when no app metadata was
decoded. App metadata follows the same packet-local or flow-derived source as
text and CSV output. ARP packets include an additional `arp` object with
`operation`, `sender_mac`, `sender_ip`, `target_mac`, and `target_ip` fields;
this field is absent for non-ARP packets.

```json
{"timestamp":"1710000000.000000","packet_number":1,"transport":{"protocol":"tcp","src_ip":"10.0.0.1","src_port":51432,"dst_ip":"10.0.0.2","dst_port":80},"packet_length":72,"payload":{"length":18,"preview_length":18,"truncated":false,"hex":"47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a 0d 0a","ascii":"GET / HTTP/1.1...."},"app":{"protocol":"http","method":"GET","path":"/","version":"HTTP/1.1"},"app_decode_status":"decoded","app_source":"packet"}
```

In JSON mode, startup, stop, flow-event, and stats text are suppressed on
stdout so consumers can parse stdout as JSON Lines. Errors still go to stderr.

## Offline Pcap

Use `--read <file.pcap>` to process an existing capture through the same
parser, filters, output, stats, JSON, and CSV logging pipeline as live capture:

```sh
./MiniSniffer --read capture.pcap --protocol tcp --count 10 --stats
```

Offline reads do not select or open a live interface, so they do not require
`sudo` or packet capture permissions.

Use `--write <file.pcap>` to save only displayed packets to a new pcap file:

```sh
./MiniSniffer --read capture.pcap --protocol tcp --write tcp-only.pcap
sudo ./MiniSniffer --interface en0 --count 100 --write sample.pcap
```

The output pcap path must not already exist. MiniSniffer creates it exclusively
with owner-only permissions and writes packets after filtering, preserving the
source packet timestamps and libpcap link type.

## Application Decoding Limits

Without `--reassemble`, application decoding is packet-local:

- HTTP/1.x is decoded only when the complete header block is inside one packet.
- UDP DNS is decoded packet-locally.
- DNS over TCP is decoded only when the full two-byte length-prefixed DNS frame is inside one packet.
- TLS is decoded only when the full ClientHello record is inside one packet.
- mDNS (UDP port 5353) reuses the same DNS message parser and is always
  packet-local; it is not eligible for TCP stream reassembly.
- DHCP (UDP ports 67/68) requires the fixed BOOTP header plus the DHCP magic
  cookie inside one packet; it is always packet-local.
- QUIC Initial packets (UDP port 443/8443) are decoded packet-locally and only
  as far as the Source Connection ID; MiniSniffer never removes header
  protection or decrypts anything.

With `--reassemble`, TCP streams are reassembled conservatively with bounded
per-direction buffers. HTTP headers, TLS ClientHello records, and DNS-over-TCP
frames can be decoded after they span multiple in-order or simply reordered TCP
segments. Data that exceeds configured memory caps is dropped instead of growing
without bound. mDNS, DHCP, and QUIC are UDP-only and never participate in TCP
stream reassembly.

IPv4 fragments are tracked independently from TCP stream reassembly. Fragments
are keyed by source, destination, protocol, and IPv4 identification, then held
under strict datagram-count, byte, and timeout caps. Individual fragments keep
their coarse packet summaries; transport ports, payload filters, and app
metadata are decoded only after a complete datagram is safely assembled.
Overlapping fragments invalidate the datagram instead of choosing one byte
sequence over another.

Flow tracking is bounded by `--max-flows`. Only TCP flows are tracked, and each
direction's storage is allocated lazily when payload arrives. The CLI enforces
per-setting and aggregate memory ceilings. Each direction has its own fixed
stream buffer; data that cannot fit is dropped rather than reallocating the
buffer.

### TCP Reassembly Model

The reassembly model is intentionally conservative rather than a full TCP
stack:

- **Sequencing** uses serial-number arithmetic, so it stays correct across a
  32-bit sequence-number wraparound.
- **In-order data** is appended directly to the per-direction stream buffer.
- **Out-of-order data** (a gap) is copied into a small bounded pending store
  (at most 8 segments, and bounded to the same byte cap as the stream buffer
  itself). A gap is counted every time a segment arrives ahead of the expected
  sequence, whether or not it can be buffered.
- **Retransmissions** (a segment that ends at or before the already-accepted
  sequence) are counted and ignored without touching the stream.
- **Overlaps** are trimmed with a fixed policy: keep the bytes already
  accepted, append only the new tail of an overlapping segment. MiniSniffer
  never rewrites bytes already placed in the stream.
- **Memory caps**: once a segment cannot fit in the stream buffer or the
  pending store is full (segment count or byte cap), further data for that
  direction is dropped. The direction is marked unusable rather than growing
  memory to make room.
- **FIN/RST tracking**: FIN and RST flags are tracked for every TCP segment in
  a flow, including segments with no payload (bare ACK/FIN/RST packets) and
  segments arriving after the flow has already been classified. A flow is
  considered closed once either direction has seen RST, or both directions
  have seen FIN. Closed flows are proactively removed from the flow table
  instead of waiting for the idle timeout, freeing their memory sooner.
- **Buffer release on classification**: once a flow's application metadata has
  been classified (from either a packet-local decode or a completed stream
  decode), its stream and pending-segment buffers are freed immediately, since
  nothing reads them again. FIN/RST tracking keeps working afterward with no
  buffer allocated.
- **Flows discovered mid-stream**: MiniSniffer never requires seeing a
  connection's SYN. The first captured segment for a direction becomes the
  sequencing baseline, so a flow whose earlier packets were missed (capture
  started late, or the flow was already several packets old when first seen)
  is still tracked and classified normally from whatever point capture began.
- **Eviction** happens three ways: idle timeout (`--flow-timeout`), capacity
  pressure (least-recently-seen flow evicted when `--max-flows` is reached),
  and proactive closed-flow cleanup (FIN/RST, described above). All three are
  counted separately in `--stats`.

This is not a full TCP stack: it does not implement retransmission timers,
congestion control, window scaling, or connection state beyond "reassembling
enough bytes to decode application metadata, and knowing when to stop."

## CSV Logging

Use `--log <file>` to write displayed packets to CSV:

```sh
sudo ./MiniSniffer --count 25 --log packets.csv
```

The log path must not already exist. MiniSniffer creates it atomically with
owner-only permissions (`0600`) and refuses existing files and symbolic links.
This prevents privileged runs from truncating an attacker-selected file.

CSV columns:

```text
packet_number,protocol,src_ip,src_port,dst_ip,dst_port,size
```

Packets without ports leave the `src_port` and `dst_port` fields empty.

When `--payload` is enabled, CSV logs include three additional columns:

```text
payload_length,payload_hex,payload_ascii
```

Payload CSV values are bounded by `--payload-bytes`.

When `--decode-app` is enabled, CSV logs use the stable application schema:

```text
timestamp,src_ip,src_port,dst_ip,dst_port,transport_protocol,packet_length,app_protocol,http_method,http_host,http_path,http_status,dns_query,dns_type,dns_class,dns_rcode,tls_sni,tls_alpn,tls_record_version,tls_client_version,app_source,dhcp_message_type,dhcp_transaction_id,dhcp_client_mac,dhcp_client_ip,dhcp_your_ip,dhcp_server_ip,dhcp_requested_ip,quic_version,quic_dcid,quic_scid,arp_operation,arp_sender_mac,arp_target_mac
```

`app_source` is `packet` for packet-local metadata, `flow` for stream-derived
flow metadata, or `none` when no app metadata is available. mDNS rows reuse the
`dns_query`/`dns_type`/`dns_class`/`dns_rcode` columns with `app_protocol` set
to `mdns`, since mDNS is wire-compatible with DNS. The `dhcp_*`, `quic_*`, and
`arp_*` columns were added additively at the end of the schema; `arp_*` columns
are populated from packet-level ARP metadata regardless of `app_protocol`.

CSV app rows keep the same metadata columns for compatibility. Decode status is
reported in text, JSON, and stats output.

By default, CSV logging flushes each row (`--flush-log line`), matching the
existing safe behavior for long-running captures. `--flush-log always` is
accepted as an explicit synonym for row flushing, and `--flush-log exit` buffers
rows until close for higher throughput when losing the last buffered rows on
process failure is acceptable.

Text cells escape control bytes and neutralize leading spreadsheet formula
characters before writing, so opening captured metadata in spreadsheet software
does not evaluate network-supplied formulas.

## Stats

Use `--stats` to print a summary after capture completes:

```sh
sudo ./MiniSniffer --count 50 --stats
```

The stats summary includes:

- Displayed packet count
- Raw packets seen (every packet libpcap delivered, before filtering)
- Packets filtered out (parsed successfully but did not pass active filters)
- Parse failures (packets the parser could not summarize at all; skipped, not fatal)
- TCP packet count
- UDP packet count
- ICMP packet count
- ARP packet count
- Other packet count
- Total displayed bytes
- Average displayed packet size
- IPv4 fragments seen
- IPv4 fragments reassembled
- IPv4 fragments expired
- IPv4 fragments malformed
- IPv4 fragments dropped due to caps
- IPv4 fragment reassembly memory currently in use and the configured maximum
- Pcap driver packets received, dropped, and interface drops, when available
- App decode no_match, need_more, malformed, truncated, and decoded counters
- Flows created
- Flows active when capture ended
- Flows closed via FIN and via RST
- Flows evicted due to idle timeout and due to `--max-flows` capacity pressure
- Flow retransmissions, out-of-order segments, overlapping segments, and gaps
- Flow stream bytes currently in use and the configured maximum

Stats count displayed packets only for the per-protocol and byte counters;
filtered-out packets are tracked separately via the "packets filtered out"
counter above. Raw packets seen, filtered out, and parse failures are always
tracked, whether or not `--reassemble` is used. Flow counters reflect the
whole `--reassemble` run and are populated once, at the end of capture; they
are all zero when `--reassemble` is not used. Pcap driver counters
(`pcap_stats`) are only queried for live captures; offline reads (`--read`) and
platforms that do not support driver-level counters report them as
unavailable.

A single packet the parser cannot summarize no longer aborts the whole
capture: it is counted as a parse failure and skipped, so a live capture
keeps running past occasional malformed or truncated packets. This applies to
both directly captured packets and packets reassembled from IPv4 fragments.

## Tests

Run the unit test suite:

```sh
make test
```

The test target builds and runs tests for config parsing, CLI parsing, packet
parsing, filtering, flow tracking, TCP reassembly, stream buffering,
IPv4 fragment reassembly, application decoders, CSV logging, stats, and basic
capture validation. It also runs `make clean` after the tests complete.

Run the same suite with AddressSanitizer and UndefinedBehaviorSanitizer:

```sh
make sanitize
```

Run all available local checks:

```sh
make check
```

`make check` runs the unit tests, sanitizer build, format check, and static
analysis check. Format and static checks are skipped with a message when their
tools are not installed.

Format source files with clang-format:

```sh
make format
```

Check formatting without editing files:

```sh
make format-check
```

Run static analysis with clang-tidy when available, or cppcheck when available:

```sh
make static-check
```

## Benchmarks

Run lightweight local benchmarks for the parser, app decoders, filters, and
TCP reassembly:

```sh
make bench
```

Each benchmark runs a fixed iteration count of one hot function against
synthetic in-memory data and reports throughput:

```text
Running bench_parser...
parser_parse_packet                  500000 iters    0.1812 s         2759717 ops/sec       362.4 ns/op
```

These are simple wall-clock loop benchmarks meant to catch gross regressions
or compare before/after changes locally, not a statistical benchmarking
framework. `make bench` builds and runs `bench_parser`, `bench_app_decoder`
(HTTP, DNS, TLS, and signature-sniffed decoding), `bench_filters`, and
`bench_reassembly`, then runs `make clean` afterward, matching `make test`.

## Fuzzing

Fuzzing harnesses live under `fuzz/` for the parser, DNS (raw UDP,
TCP-framed, and mDNS decode paths), HTTP, TLS ClientHello, app-protocol
dispatch, TCP stream reassembly, and offline pcap ingestion. Each harness
exposes the standard libFuzzer entry point:

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
```

Every harness object links two ways:

- With `-fsanitize=fuzzer,address,undefined`, as a real libFuzzer binary that
  performs coverage-guided mutation (`make fuzz-build`).
- With `fuzz/fuzz_standalone_main.c` instead, using only
  `-fsanitize=address,undefined`, producing a `<target>_smoke` binary that
  replays a fixed list of files once each. This works even on toolchains
  without a linked libFuzzer runtime (for example, a bare Xcode Command Line
  Tools install on macOS), so smoke testing never requires installing
  anything beyond a working C compiler.

No harness requires root or a live network interface: the pcap harness feeds
fuzz bytes to libpcap through `fmemopen` as an in-memory offline savefile
instead of opening an interface or touching disk, and the reassembly harness
drives `tcp_reassembly_process_segment` directly against one in-process
`TcpReassemblyDirection` rather than a live TCP flow.

A small seed corpus lives under `fuzz/corpus/<target>/`, derived from the
same fixtures the unit tests use (`tests/fixtures/app_fixtures.h`), plus a
handful of hand-built truncated and malformed variants and a minimal
two-packet `.pcap` file.

Build and run every fuzz target once against its seed corpus under
AddressSanitizer/UndefinedBehaviorSanitizer:

```sh
make fuzz-smoke
```

Build the real libFuzzer binaries. This is skipped with a message, rather
than a hard failure, on toolchains without a linked libFuzzer runtime:

```sh
make fuzz-build
```

Run a brief, bounded coverage-guided session per target, the same command CI
uses. Defaults to 20 seconds per target; override with `FUZZ_CI_SECONDS`:

```sh
make fuzz-ci
```

`fuzz-smoke` and `fuzz-ci` both run `make clean` afterward, matching `make
test` and `make bench`. `fuzz-build` leaves its binaries in place instead, for
interactive fuzzing beyond the bounded CI run, such as
`./fuzz_parser -max_total_time=60 fuzz/corpus/parser`.

## Man Page

A man page lives at `man/minisniffer.1`, covering the same options and a few
of the same examples as this README. View it directly without installing:

```sh
man ./man/minisniffer.1
```

`make install` installs it to `$(MANDIR)/minisniffer.1` (default
`$(PREFIX)/share/man/man1/minisniffer.1`), after which `man minisniffer` works
normally.

## Shell Completions

Bash, zsh, and fish completions live under `completions/`, covering every
current flag and, where the CLI accepts a fixed set of values (`--protocol`,
`--app`, `--domain-match`, `--flush-log`, `--dns-type`, `--dhcp-type`, and
known HTTP methods), completing those values too.

`make install` installs all three automatically. To use them without
installing:

```sh
# bash: source directly, or copy into your completions directory
source completions/minisniffer.bash

# zsh: add the completions/ directory to fpath, then compinit
fpath=(completions $fpath)
autoload -U compinit && compinit

# fish: copy (or symlink) into fish's user completions directory
cp completions/minisniffer.fish ~/.config/fish/completions/minisniffer.fish
```

## Continuous Integration

GitHub Actions workflows are included for the expected quality gates. They are
currently configured for manual `workflow_dispatch` runs so they do not consume
minutes on every push or pull request. Re-enable `push` and `pull_request`
triggers when CI minutes are available.

- Ubuntu builds with GCC and Clang
- macOS builds with Clang
- `make test`
- `make sanitize`
- `make format-check`
- `make static-check`
- LLVM coverage generation
- CodeQL analysis for C/C++
- `make fuzz-smoke` and a brief bounded `make fuzz-ci` run per fuzz target

CI installs libpcap development headers on Ubuntu and Homebrew libpcap on macOS.
Formatting and static-analysis checks may skip only when the corresponding tool
is unavailable; if a tool is installed and finds a problem, CI should fail.

The dedicated `fuzz` CI job installs `clang` and `llvm` (for the libFuzzer
runtime) and runs `make CC=clang fuzz-smoke` followed by
`make CC=clang FUZZ_CI_SECONDS=20 fuzz-ci`; any crash, OOM, leak, or timeout
artifact left behind by a fuzz session is uploaded so it can be downloaded and
reproduced locally.

### Release Workflow

`.github/workflows/release.yml` is a separate, also manually triggered
workflow for cutting a release. Unlike the CI and CodeQL workflows, it takes a
required `tag` input (an existing tag such as `v0.3.0`) rather than running
against a branch tip, so the build is reproducible from a fixed ref. It checks
out that tag, runs `make test` and `make coverage`, builds `.tar.gz` and `.zip`
source archives with `git archive` plus a `SHA256SUMS` checksum file, uploads
the coverage report and test output as workflow-run artifacts, and creates (or
updates) a GitHub release for the tag with the source archives and checksums
attached. Pushing a tag does not trigger it by itself; run it manually from
the Actions tab after the tag already exists.

Run the full suite with LLVM line and branch coverage:

```sh
make coverage
```

The coverage profile, line-by-line report, JSON summary, and captured test
output are written to `/tmp/minisniffer-coverage` by default. Set
`COVERAGE_DIR` to use another directory.

Rebuild the executable after running tests:

```sh
make
```

## Clean

Remove build artifacts:

```sh
make clean
```

## Troubleshooting

### Permission denied opening `/dev/bpf*`

On macOS, this means the process does not have permission to capture packets:

```text
cannot open BPF device: Permission denied
```

Run with `sudo`:

```sh
sudo ./MiniSniffer --count 5
```

### Wrong interface selected

List interfaces, then pass the interface explicitly:

```sh
./MiniSniffer --list-interfaces
sudo ./MiniSniffer --interface en0 --count 5
```

### Interface not found

If you see:

```text
Error: interface 'fake0' was not found.
```

Use an interface name available to libpcap on your machine. Common macOS names
include `en0` for Wi-Fi or Ethernet, depending on hardware and configuration.
Run `./MiniSniffer --list-interfaces` to see the names libpcap reports.

### Invalid CLI input

MiniSniffer validates common input mistakes before capture starts, including
unknown options, missing option values, invalid protocols, invalid ports,
invalid IP hosts, invalid app filter combinations, invalid payload and
reassembly limits, invalid domain matching modes, and log files that cannot be
opened.

Examples:

```sh
./MiniSniffer --port
./MiniSniffer --port abc
./MiniSniffer --protocol fake
./MiniSniffer --host 999.1.1.1
./MiniSniffer --payload-bytes 999
./MiniSniffer --payload-decode-bytes 999999
./MiniSniffer --payload-hex abc
./MiniSniffer --reassemble
./MiniSniffer --decode-app --max-flows 0
./MiniSniffer --decode-app --stream-buffer-bytes 0
./MiniSniffer --domain-match idna
./MiniSniffer --interface fake0
./MiniSniffer --log /bad/path/file.csv
```

## Project Layout

```text
include/          Public headers
src/              MiniSniffer implementation
tests/            Unit tests
bench/            Lightweight local benchmarks
fuzz/             Fuzzing harnesses, seed corpus, and standalone smoke driver
man/              Man page (minisniffer.1)
completions/      Bash, zsh, and fish shell completions
packaging/        Packaging metadata (Homebrew formula, etc.)
docs/             Architecture and project documentation
Makefile          Build, test, bench, fuzz, check, install, and clean targets
README.md         Project documentation
```

Important modules:

- `src/cli.c` parses command-line options into runtime configuration.
- `src/capture.c` selects an interface, opens libpcap, and runs capture.
- `src/parser.c` selects supported link-layer offsets and parses IPv4/IPv6 packet metadata.
- `src/filters.c` applies protocol, port, host, payload, and app filters.
- `src/app_decoder.c` dispatches packet-local and stream app decoders.
- `src/app_dhcp.c` decodes DHCP metadata over UDP ports 67/68.
- `src/app_dns.c` decodes DNS query metadata and, via the same parser, mDNS
  query metadata over UDP port 5353.
- `src/app_quic.c` decodes conservative QUIC Initial-packet version/DCID/SCID
  metadata over UDP ports 443/8443.
- `src/ipv4_frag.c` handles bounded IPv4 fragment reassembly.
- `src/tcp_reassembly.c` and `src/stream_buffer.c` handle bounded stream assembly.
- `src/flow.c` tracks bounded flow state and app classification.
- `src/csv_logger.c` writes displayed packets to CSV.
- `src/stats.c` tracks displayed packet counters.

## Limitations

- MiniSniffer parses Ethernet, raw IPv4/IPv6, Linux cooked capture v1/v2, and
  BSD null/loopback captures when libpcap reports those datalink types.
- Fragmented IPv4 datagrams retain coarse protocol/address metadata until a
  complete datagram is assembled within the configured internal caps.
- TCP and UDP ports are parsed only when enough header bytes were captured.
- IPv4 total length, IPv6 payload length, and UDP length fields bound transport
  payload views; link-layer padding is never treated as payload.
- Payload display and legacy payload CSV output are bounded to 256 bytes.
- Payload filters and packet-local app decoders inspect a bounded decode window,
  configured separately from payload preview length.
- IPv6 extension-header walking is conservative; fragments, ESP, truncated
  extension headers, and no-next-header packets are not decoded at transport
  or app layers.
- App decoding is intentionally limited to cleartext HTTP/1.x metadata, DNS
  and mDNS query metadata, TLS ClientHello metadata, DHCP metadata from the
  fixed BOOTP header and a small set of options, and conservative QUIC Initial
  packet version/DCID/SCID metadata only.
- ARP support is limited to the common Ethernet/IPv4 shape; other hardware or
  protocol address types are left as `OTHER`.
- TCP reassembly is conservative and bounded; it is not a full TCP stack. See
  [TCP Reassembly Model](#tcp-reassembly-model) for the exact sequencing,
  gap/overlap, memory-cap, and FIN/RST-cleanup behavior.
- Idle-timeout and closed-flow eviction are both opportunistic: they run when
  a new packet arrives for any tracked flow (or once more at capture
  shutdown), not on a wall-clock timer. A live capture with no further traffic
  after a flow closes will not free that flow's slot until shutdown.
- BPF pre-filtering only ever covers `--protocol` (tcp/udp/icmp/arp; `other`
  contributes no clause), `--port`, and `--host`; it is strictly an
  optimization; every displayed packet is always re-verified by the full
  software filter chain. Compile or install failures fall back to full
  software filtering rather than failing capture.
- A packet the parser cannot summarize at all is skipped and counted as a
  parse failure rather than aborting capture; this is expected to be
  extremely rare, since malformed or truncated header fields are otherwise
  handled by classifying the packet as `OTHER`.
- `pcap_stats` (packets received/dropped/interface-dropped) is only queried
  for live captures; it is not meaningful for offline reads and is not
  supported on every platform.
- CI fuzzing (`make fuzz-ci`) runs a brief bounded session per target
  (default 20 seconds, via `FUZZ_CI_SECONDS`); it is a regression smoke net,
  not a long-running continuous fuzzing campaign. `make fuzz-build` itself
  depends on the local toolchain having a linked libFuzzer runtime and skips
  with a message otherwise.
- HTTP Host, DNS query, and TLS SNI filters default to normalized domain
  matching: ASCII case-insensitive comparison with one trailing root dot
  ignored. Exact matching is available at runtime; IDNA matching requires a
  libidn2-enabled build.
- Live capture behavior depends on libpcap support and local OS permissions.
- `packaging/homebrew/minisniffer.rb` is not yet published to homebrew-core
  or a hosted tap; its stable `url`/`sha256` are placeholders until the first
  tagged release exists. `brew install --HEAD` works immediately since it
  builds from git directly.
- `.github/workflows/release.yml` requires an existing tag name as input and
  does not trigger automatically on tag push, matching this repository's
  manual-`workflow_dispatch`-only convention for all workflows.
