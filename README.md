# MiniSniffer

MiniSniffer is a small C packet sniffer and network analyzer built on
libpcap. It captures live packets, parses Ethernet/IPv4 traffic, applies
simple filters, prints readable packet summaries, optionally writes CSV logs,
and can report capture statistics when the run completes.

## Documentation

- [Architecture](docs/architecture.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [License](LICENSE)

## Features

- Live packet capture with libpcap
- Automatic default interface selection
- Explicit interface selection with `--interface`
- IPv4 packet parsing for TCP, UDP, ICMP, and other protocols
- Protocol, port, and host filters
- Bounded packet payload inspection
- Literal text and hex payload filters
- Packet-local HTTP, DNS, and TLS ClientHello metadata decoding
- Bounded TCP stream reassembly for HTTP, DNS-over-TCP, and TLS ClientHello metadata
- Application metadata filters
- CSV logging for displayed packets
- Summary statistics for displayed packets
- Clean Ctrl+C shutdown for unlimited captures
- Unit tests for the core modules

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
brew install libpcap
```

Packet capture usually requires elevated permissions. On macOS, run MiniSniffer
with `sudo` or configure BPF capture permissions for your account.

## Build

```sh
make
```

This creates the `MiniSniffer` executable in the project root.

The build uses `pkg-config --cflags --libs libpcap` when libpcap metadata is
available and falls back to `-lpcap` otherwise. Override `CC`, `CFLAGS`,
`PKG_CONFIG`, or `LDLIBS` on the `make` command line if your local toolchain
needs custom settings.

Install or uninstall the executable with:

```sh
make install
make uninstall
```

Both targets honor `PREFIX`, which defaults to `/usr/local`, and `DESTDIR` for
staged installs.

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
       [--protocol <tcp|udp|icmp|other>] [--port <number>]
       [--host <ipv4>] [--payload] [--payload-bytes <number>]
       [--payload-contains <text>] [--payload-hex <hex>] [--log <file>]
       [--read <file.pcap>] [--write <file.pcap>]
       [--json] [--flush-log <always|line|exit>]
       [--decode-app] [--reassemble] [--max-flows <number>]
       [--stream-buffer-bytes <number>] [--flow-timeout <seconds>]
       [--app <http|dns|tls>] [--http-host <host>] [--http-method <method>]
       [--dns-query <name>] [--dns-type <type>] [--tls-sni <host>]
       [--tls-alpn <protocol>] [--stats]
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
| `--protocol <tcp|udp|icmp|other>` | Display only packets matching the selected protocol. |
| `--port <number>` | Display only TCP/UDP packets where the source or destination port matches. |
| `--host <ipv4>` | Display only packets where the source or destination IPv4 address matches. |
| `--payload` | Print a bounded hex and ASCII payload preview for displayed packets. |
| `--payload-bytes <number>` | Set the payload preview length. Default is 256 bytes. Maximum is 256 bytes. |
| `--payload-contains <text>` | Display only packets whose bounded payload decode window contains the literal text. |
| `--payload-hex <hex>` | Display only packets whose bounded payload decode window contains the byte pattern. |
| `--read <file.pcap>` | Read packets from an offline pcap file instead of live capture. Does not require interface selection or capture permissions. |
| `--write <file.pcap>` | Write displayed packets to a new pcap file, preserving timestamps and link type. Existing files are refused. |
| `--json` | Print displayed packets as JSON Lines instead of human-readable packet text. |
| `--decode-app` | Decode packet-local HTTP, DNS, and TLS ClientHello metadata. |
| `--reassemble` | Enable bounded TCP stream reassembly for app decoding. Requires `--decode-app`. |
| `--max-flows <number>` | Set the maximum number of tracked TCP flows for reassembly. Default is 512; maximum is 1024. Requires `--reassemble`. |
| `--stream-buffer-bytes <number>` | Set the per-direction TCP stream buffer cap. Default is 32768 bytes; maximum is 1048576 bytes. Requires `--reassemble`. |
| `--flow-timeout <seconds>` | Evict flows idle for at least this many seconds. Default is 60 seconds. Requires `--reassemble`. |
| `--app <http|dns|tls>` | Display only packets with decoded app metadata for the selected protocol. Requires `--decode-app`. |
| `--http-host <host>` | Display only decoded HTTP packets with a matching Host header. Requires `--decode-app`. |
| `--http-method <method>` | Display only decoded HTTP requests with a matching method. Requires `--decode-app`. |
| `--dns-query <name>` | Display only decoded DNS packets with a matching first query name. Requires `--decode-app`. |
| `--dns-type <type>` | Display only decoded DNS packets with a matching first query type, such as `A` or `AAAA`. Requires `--decode-app`. |
| `--tls-sni <host>` | Display only decoded TLS ClientHello packets with a matching SNI hostname. Requires `--decode-app`. |
| `--tls-alpn <protocol>` | Display only decoded TLS ClientHello packets advertising the ALPN protocol. Requires `--decode-app`. |
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
sudo ./MiniSniffer --protocol tcp --port 443 --host 142.250.190.14 --count 10
```

Port filters apply only to packets with TCP or UDP ports. ICMP and other
packets do not match a port filter.

Payload filters inspect the bounded payload decode window, not the smaller
console/log preview. They do not require `--payload`; use `--payload` only when
you also want to print or log previews.

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

Application filter examples:

```sh
sudo ./MiniSniffer --decode-app --app http --http-host example.com
sudo ./MiniSniffer --decode-app --app dns --dns-query example.com --dns-type A
sudo ./MiniSniffer --decode-app --app tls --tls-sni example.com --tls-alpn h2
sudo ./MiniSniffer --decode-app --reassemble --app tls --tls-sni example.com --count 5
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

With `--payload`, MiniSniffer prints a bounded payload preview below each
displayed packet:

```text
[003] TCP  192.168.1.25:51432 -> 142.250.190.14:80 size=71
      payload length=17 preview=17
      hex: 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a 0d
      ascii: GET / HTTP/1.1...
```

With `--decode-app`, decoded application metadata is printed below the packet
summary when it is available:

```text
[004] TCP  192.168.1.25:51432 -> 93.184.216.34:80 size=512
      app: http method=GET host=example.com path=/
```

With `--decode-app --reassemble`, stream-derived app metadata is printed as a
flow event with the first packet from that flow that passes all active filters:

```text
flow tcp 192.168.1.25:51432 <-> 93.184.216.34:443 app=tls sni=example.com alpn=h2
```

Non-IPv4 Ethernet packets are displayed as `OTHER` when they pass the active
filters. Capture startup rejects interfaces whose libpcap data-link type is not
Ethernet, rather than interpreting another link-layer format incorrectly.

Application metadata is escaped before terminal output. Control bytes are
shown as `\xNN` text and cannot emit terminal control sequences.

Use `--json` to print displayed packets as JSON Lines:

```sh
sudo ./MiniSniffer --json --decode-app --payload --count 5
```

Each displayed packet is one JSON object with `timestamp`, `packet_number`,
`transport`, `packet_length`, optional `payload`, `app`, and `app_source`.
Payload previews include bounded `length`, `preview_length`, `truncated`, `hex`,
and `ascii` fields when `--payload` is enabled. App metadata follows the same
packet-local or flow-derived source as text and CSV output.

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

With `--reassemble`, TCP streams are reassembled conservatively with bounded
per-direction buffers. HTTP headers, TLS ClientHello records, and DNS-over-TCP
frames can be decoded after they span multiple in-order or simply reordered TCP
segments. Data that exceeds configured memory caps is dropped instead of growing
without bound.

Flow tracking is bounded by `--max-flows`. Only TCP flows are tracked, and each
direction's storage is allocated lazily when payload arrives. The CLI enforces
per-setting and aggregate memory ceilings. When the table is full after idle
eviction, MiniSniffer evicts the least recently seen flow to preserve the memory
cap. Each direction has its own fixed stream buffer; data that cannot fit is
dropped rather than reallocating the buffer.

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
timestamp,src_ip,src_port,dst_ip,dst_port,transport_protocol,packet_length,app_protocol,http_method,http_host,http_path,http_status,dns_query,dns_type,dns_class,dns_rcode,tls_sni,tls_alpn,tls_record_version,tls_client_version,app_source
```

`app_source` is `packet` for packet-local metadata, `flow` for stream-derived
flow metadata, or `none` when no app metadata is available.

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
- TCP packet count
- UDP packet count
- ICMP packet count
- Other packet count
- Total displayed bytes
- Average displayed packet size

Stats count displayed packets only. Filtered-out packets are ignored.

## Tests

Run the unit test suite:

```sh
make test
```

The test target builds and runs tests for config parsing, CLI parsing, packet
parsing, filtering, flow tracking, TCP reassembly, stream buffering,
application decoders, CSV logging, stats, and basic capture validation. It also
runs `make clean` after the tests complete.

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

CI installs libpcap development headers on Ubuntu and Homebrew libpcap on macOS.
Formatting and static-analysis checks may skip only when the corresponding tool
is unavailable; if a tool is installed and finds a problem, CI should fail.

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
invalid IPv4 hosts, invalid app filter combinations, invalid reassembly limits,
and log files that cannot be opened.

Examples:

```sh
./MiniSniffer --port
./MiniSniffer --port abc
./MiniSniffer --protocol fake
./MiniSniffer --host 999.1.1.1
./MiniSniffer --payload-bytes 999
./MiniSniffer --payload-hex abc
./MiniSniffer --reassemble
./MiniSniffer --decode-app --max-flows 0
./MiniSniffer --decode-app --stream-buffer-bytes 0
./MiniSniffer --interface fake0
./MiniSniffer --log /bad/path/file.csv
```

## Project Layout

```text
include/          Public headers
src/              MiniSniffer implementation
tests/            Unit tests
docs/             Architecture and project documentation
Makefile          Build, test, check, install, and clean targets
README.md         Project documentation
```

Important modules:

- `src/cli.c` parses command-line options into runtime configuration.
- `src/capture.c` selects an interface, opens libpcap, and runs capture.
- `src/parser.c` parses Ethernet/IPv4 packet metadata.
- `src/filters.c` applies protocol, port, host, payload, and app filters.
- `src/app_decoder.c` dispatches packet-local and stream app decoders.
- `src/tcp_reassembly.c` and `src/stream_buffer.c` handle bounded stream assembly.
- `src/flow.c` tracks bounded flow state and app classification.
- `src/csv_logger.c` writes displayed packets to CSV.
- `src/stats.c` tracks displayed packet counters.

## Limitations

- MiniSniffer currently parses Ethernet IPv4 packets.
- Fragmented IPv4 datagrams retain coarse protocol/address metadata but are not
  decoded at the transport or application layers because IP reassembly is not
  implemented.
- TCP and UDP ports are parsed only when enough header bytes were captured.
- IPv4 total length and UDP length fields bound all transport payload views;
  Ethernet padding is never treated as payload.
- Payload display and legacy payload CSV output are bounded to 256 bytes.
- Payload filters and packet-local app decoders inspect a bounded decode window.
- IPv6 packet parsing is not implemented.
- App decoding is intentionally limited to cleartext HTTP/1.x metadata, DNS
  query metadata, and TLS ClientHello metadata.
- TCP reassembly is conservative and bounded; it is not a full TCP stack.
- HTTP Host, DNS query, and TLS SNI filters compare domain names without ASCII
  case sensitivity and ignore one trailing root dot.
- Live capture behavior depends on libpcap support and local OS permissions.
