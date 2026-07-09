# MiniSniffer Architecture

MiniSniffer is organized as a small, bounded packet-processing pipeline:

```text
capture -> parser -> flow/reassembly -> app decoder -> filters -> output/logger -> stats
```

Each stage keeps a narrow responsibility so packet data remains easier to
validate, bound, and test.

## Pipeline

### Capture

`src/capture.c` selects a libpcap interface, validates that the link type is
Ethernet, opens the capture handle, and drives the packet loop. It owns live
capture concerns such as default interface selection, capture errors, Ctrl+C
shutdown, and per-packet dispatch.

Capture startup uses the parsed `AppConfig` from `src/cli.c` and
`src/config.c`. Packet capture usually requires elevated operating-system
permissions, but MiniSniffer does not attempt to bypass those permissions.

### Parser

`src/parser.c` converts raw Ethernet frames into bounded packet metadata. It
currently handles Ethernet IPv4 packets and extracts protocol, address, port,
size, timestamp, and payload-view information when enough bytes are present.

The parser treats packet bytes as untrusted input. IPv4 total length and UDP
length fields bound transport payload views, and Ethernet padding is not
treated as payload.

### Flow and Reassembly

`src/flow.c`, `src/tcp_reassembly.c`, and `src/stream_buffer.c` track bounded
TCP flow state when `--decode-app --reassemble` is enabled. Flow tracking is
limited by `--max-flows`, `--stream-buffer-bytes`, and `--flow-timeout`.

Reassembly is conservative. It is intended to recover enough in-order or simply
reordered TCP stream data for HTTP headers, DNS-over-TCP frames, and TLS
ClientHello metadata. It is not a full TCP stack.

### App Decoder

`src/app_decoder.c` dispatches to packet-local and stream-derived decoders for
the supported application metadata:

- HTTP/1.x request and response metadata
- DNS query metadata
- TLS ClientHello SNI and ALPN metadata

Packet-local decoding is enabled with `--decode-app`. Stream-derived decoding
requires `--decode-app --reassemble`. MiniSniffer does not decrypt traffic.
TLS support is limited to clear ClientHello metadata.

### Filters

`src/filters.c` applies configured filters with AND semantics. A packet must
match every enabled filter before it is printed, logged, counted, or included
in stats.

Supported filters include:

- `--protocol <tcp|udp|icmp|other>`
- `--port <number>`
- `--host <ipv4>`
- `--payload-contains <text>`
- `--payload-hex <hex>`
- `--app <http|dns|tls>`
- `--http-host <host>`
- `--http-method <method>`
- `--dns-query <name>`
- `--dns-type <type>`
- `--tls-sni <host>`
- `--tls-alpn <protocol>`

Application filters require `--decode-app`. Reassembly-related flow settings
require `--decode-app --reassemble`.

### Output and Logger

`src/output.c` prints packet summaries, bounded payload previews, decoded app
metadata, and stream classification events. Output escapes control bytes so
network-supplied metadata cannot emit terminal control sequences.

`src/csv_logger.c` writes displayed packets to CSV when `--log <file>` is set.
Log files are created atomically with owner-only permissions and existing paths
are refused. Text cells escape control bytes and neutralize leading spreadsheet
formula characters.

### Stats

`src/stats.c` tracks displayed packet totals when `--stats` is enabled. Stats
count packets after filtering, not all raw captured packets.

## Safety and Scope

MiniSniffer is for learning, local diagnostics, and authorized network
observation. It is not for MITM, credential capture, decryption, injection,
stealth, evasion, persistence, or use on networks you do not own or have
explicit permission to inspect.

The project intentionally focuses on bounded parsing, metadata extraction,
filtering, logging, and statistics. Contributions should preserve those bounds
and avoid features that would turn MiniSniffer into an offensive or covert
network tool.

## Current Limits

- Ethernet IPv4 parsing only
- No IPv6 parser
- No IP reassembly
- TCP and UDP ports only when enough header bytes were captured
- Bounded payload inspection and payload display
- Cleartext HTTP/1.x metadata only
- DNS query metadata only
- TLS ClientHello metadata only
- Conservative bounded TCP reassembly, not a full TCP stack
