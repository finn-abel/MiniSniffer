# MiniSniffer

MiniSniffer is a small C packet sniffer and network analyzer built on
libpcap. It captures live packets, parses Ethernet/IPv4 traffic, applies
simple filters, prints readable packet summaries, optionally writes CSV logs,
and can report capture statistics when the run completes.

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
Usage: ./MiniSniffer [--help] [--interface <name>] [--count <number>]
       [--protocol <tcp|udp|icmp|other>] [--port <number>]
       [--host <ipv4>] [--payload] [--payload-bytes <number>]
       [--payload-contains <text>] [--payload-hex <hex>] [--log <file>]
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
| `--interface <name>` | Capture from a specific interface, such as `en0`. |
| `--count <number>` | Stop after this many displayed packets. If omitted, capture continues until Ctrl+C. |
| `--protocol <tcp|udp|icmp|other>` | Display only packets matching the selected protocol. |
| `--port <number>` | Display only TCP/UDP packets where the source or destination port matches. |
| `--host <ipv4>` | Display only packets where the source or destination IPv4 address matches. |
| `--payload` | Print a bounded hex and ASCII payload preview for displayed packets. |
| `--payload-bytes <number>` | Set the payload preview length. Default is 256 bytes. Maximum is 256 bytes. |
| `--payload-contains <text>` | Display only packets whose bounded payload decode window contains the literal text. |
| `--payload-hex <hex>` | Display only packets whose bounded payload decode window contains the byte pattern. |
| `--decode-app` | Decode packet-local HTTP, DNS, and TLS ClientHello metadata. |
| `--reassemble` | Enable bounded TCP stream reassembly for app decoding. Requires `--decode-app`. |
| `--max-flows <number>` | Set the maximum number of tracked flows for reassembly. Default is 4096. Requires `--reassemble`. |
| `--stream-buffer-bytes <number>` | Set the per-direction TCP stream buffer cap. Default is 65536 bytes. Requires `--reassemble`. |
| `--flow-timeout <seconds>` | Evict flows idle for at least this many seconds. Default is 60 seconds. Requires `--reassemble`. |
| `--app <http|dns|tls>` | Display only packets with decoded app metadata for the selected protocol. Requires `--decode-app`. |
| `--http-host <host>` | Display only decoded HTTP packets with a matching Host header. Requires `--decode-app`. |
| `--http-method <method>` | Display only decoded HTTP requests with a matching method. Requires `--decode-app`. |
| `--dns-query <name>` | Display only decoded DNS packets with a matching first query name. Requires `--decode-app`. |
| `--dns-type <type>` | Display only decoded DNS packets with a matching first query type, such as `A` or `AAAA`. Requires `--decode-app`. |
| `--tls-sni <host>` | Display only decoded TLS ClientHello packets with a matching SNI hostname. Requires `--decode-app`. |
| `--tls-alpn <protocol>` | Display only decoded TLS ClientHello packets advertising the ALPN protocol. Requires `--decode-app`. |
| `--log <file>` | Write displayed packets to a CSV file. |
| `--stats` | Print displayed packet totals after capture completes. |

`--count` is applied after filtering. For example, `--protocol tcp --count 10`
stops after ten displayed TCP packets, not after ten raw packets.

## Interface Selection

When `--interface` is omitted, MiniSniffer enumerates libpcap devices and
chooses a practical default. On macOS it prefers normal non-loopback IPv4
interfaces such as `en0` and avoids common internal or tunnel interfaces such
as `ap*`, `awdl*`, `llw*`, and `utun*`.

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
flow event when the flow is first classified:

```text
flow tcp 192.168.1.25:51432 <-> 93.184.216.34:443 app=tls sni=example.com alpn=h2
```

Packets that cannot be parsed as Ethernet/IPv4 are displayed as `OTHER` when
they pass the active filters.

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

Flow tracking is bounded by `--max-flows`. When the table is full after idle
eviction, MiniSniffer evicts the least recently seen flow to preserve the memory
cap. Each direction has its own fixed stream buffer; data that cannot fit is
dropped rather than reallocating the buffer.

## CSV Logging

Use `--log <file>` to write displayed packets to CSV:

```sh
sudo ./MiniSniffer --count 25 --log packets.csv
```

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
make test CFLAGS='-Wall -Wextra -Werror -std=c11 -g -fsanitize=address,undefined -fno-omit-frame-pointer'
```

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

Pass the interface explicitly:

```sh
sudo ./MiniSniffer --interface en0 --count 5
```

### Interface not found

If you see:

```text
Error: interface 'fake0' was not found.
```

Use an interface name available to libpcap on your machine. Common macOS names
include `en0` for Wi-Fi or Ethernet, depending on hardware and configuration.

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
Makefile          Build, test, and clean targets
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
- TCP and UDP ports are parsed only when enough header bytes were captured.
- Payload display and legacy payload CSV output are bounded to 256 bytes.
- Payload filters and packet-local app decoders inspect a bounded decode window.
- IPv6 packet parsing is not implemented.
- App decoding is intentionally limited to cleartext HTTP/1.x metadata, DNS
  query metadata, and TLS ClientHello metadata.
- TCP reassembly is conservative and bounded; it is not a full TCP stack.
- Live capture behavior depends on libpcap support and local OS permissions.
