# MiniSniffer Architecture

MiniSniffer is organized as a small, bounded packet-processing pipeline:

```text
capture -> parser -> fragment/flow reassembly -> app decoder -> filters -> output/logger -> stats
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

`src/parser.c` converts supported libpcap link-layer packets into bounded
packet metadata. It handles IPv4 and IPv6 packets and extracts protocol,
address, port, ICMP, size, timestamp, and payload-view information when enough
bytes are present.

ARP is also recognized directly from the Ethernet ethertype. Support is
conservative: only the common Ethernet/IPv4 ARP shape (`htype=1`, `ptype=0x0800`,
`hlen=6`, `plen=4`) is decoded into operation, sender/target IP, and
sender/target MAC metadata. Anything else is left as `OTHER` rather than
attempting variable hardware/protocol address length parsing.

The parser treats packet bytes as untrusted input. IPv4 total length, IPv6
payload length, and UDP length fields bound transport payload views, and
link-layer padding is not treated as payload. The payload preview length and
payload decode window are separate caps: `--payload-bytes` controls text/CSV
preview output, while `--payload-decode-bytes` controls payload filters and
packet-local app decoder input.

### Flow and Reassembly

`src/ipv4_frag.c` tracks bounded IPv4 fragment state keyed by source,
destination, protocol, and identification. Complete datagrams are reconstructed
only under count, byte, and timeout caps; overlapping fragments invalidate the
datagram.

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
- DNS query metadata (`src/app_dns.c`)
- TLS ClientHello SNI and ALPN metadata
- DHCP message type, transaction ID, client MAC, and address metadata over UDP
  67/68 (`src/app_dhcp.c`)
- mDNS query metadata over UDP 5353, reusing the DNS wire-format parser in
  `src/app_dns.c` (`app_dns_decode_mdns_message`/`app_dns_decode_mdns_udp`)
- Conservative QUIC Initial-packet metadata over UDP 443/8443: version,
  Destination Connection ID, and Source Connection ID only (`src/app_quic.c`)

Packet-local decoding is enabled with `--decode-app`. Stream-derived decoding
requires `--decode-app --reassemble` and only applies to TCP (HTTP, TLS,
DNS-over-TCP); DHCP, mDNS, and QUIC are UDP-only and are always decoded
packet-locally. MiniSniffer does not decrypt traffic. TLS support is limited to
clear ClientHello metadata, and QUIC support stops parsing immediately after the
Source Connection ID — the Token, Length, packet number, and payload either
require removing header protection or are encrypted outright, and MiniSniffer
never attempts either.

Decoder results are reduced to stable status values for observability:
`no_match`, `need_more`, `malformed`, `truncated`, and `decoded`. Text and JSON
output expose the per-packet status, and stats count displayed packets by
status.

### Filters

`src/filters.c` applies configured filters with AND semantics. A packet must
match every enabled filter before it is printed, logged, counted, or included
in stats.

Supported filters include:

- `--protocol <tcp|udp|icmp|arp|other>`
- `--port <number>`
- `--host <ip>`
- `--payload-contains <text>`
- `--payload-hex <hex>`
- `--app <http|dns|tls|dhcp|mdns|quic>`
- `--http-host <host>`
- `--http-method <method>`
- `--dns-query <name>` (matches both DNS and mDNS, since mDNS reuses the same
  `dns_query_name` field)
- `--dns-type <type>` (matches both DNS and mDNS)
- `--tls-sni <host>`
- `--tls-alpn <protocol>`
- `--dhcp-type <type>`
- `--quic-version <version>`

Application filters require `--decode-app`. Reassembly-related flow settings
require `--decode-app --reassemble`. ARP has no transport ports; sender/target
IPv4 addresses populate the same `src_ip`/`dst_ip` fields as other protocols, so
`--protocol arp` and `--host <ip>` filters work without special-casing ARP.

HTTP Host, DNS query, and TLS SNI filters use `--domain-match` to select
comparison behavior. The default `normalized` mode is ASCII case-insensitive
and ignores one trailing root dot. `exact` mode uses byte-for-byte comparison.
`idna` mode is available only in builds compiled with `WITH_LIBIDN2=1`; it uses
libidn2 conversion before normalized comparison.

### Output and Logger

`src/output.c` prints packet summaries, bounded payload previews, decoded app
metadata, app decode status, and stream classification events. Output escapes
control bytes so network-supplied metadata cannot emit terminal control
sequences.

`src/csv_logger.c` writes displayed packets to CSV when `--log <file>` is set.
Log files are created atomically with owner-only permissions and existing paths
are refused. Text cells escape control bytes and neutralize leading spreadsheet
formula characters.

### Stats

`src/stats.c` tracks displayed packet totals when `--stats` is enabled. Stats
count packets after filtering, not all raw captured packets. IPv4 fragment
counters track fragments seen, reassembled, expired, malformed, and dropped due
to caps. App decode counters track displayed packet statuses for no match,
incomplete input, malformed input, truncation by configured caps, and successful
decodes.

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

- Supported datalink parsing only: Ethernet, raw IPv4/IPv6, Linux cooked v1/v2,
  and BSD null/loopback
- IPv4 fragment reassembly is bounded and rejects overlaps
- TCP and UDP ports only when enough header bytes were captured
- Bounded payload inspection and payload display
- Payload decode and payload preview use separate bounded windows
- Cleartext HTTP/1.x metadata only
- DNS and mDNS query metadata only
- TLS ClientHello metadata only
- DHCP metadata limited to the fixed BOOTP header, message type, and requested
  IP option
- QUIC metadata limited to visible Initial-packet version/DCID/SCID; no header
  protection removal or decryption is attempted
- ARP metadata limited to the common Ethernet/IPv4 shape
- Conservative bounded TCP reassembly, not a full TCP stack
