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

After confirming a supported datalink type, `install_bpf_filter` compiles and
installs a BPF pre-filter (`pcap_compile`/`pcap_setfilter`) when
`build_bpf_filter_expression` can build one from the simple filters enabled
(`--protocol` for tcp/udp/icmp/arp, `--port`, `--host`) and `--no-bpf` was not
passed. This runs identically for live and offline (`--read`) captures. It is
purely an optimization: it only ever reduces how many packets libpcap
delivers to the process; every displayed packet is still fully re-checked by
`src/filters.c` afterward, so a compile or install failure (logged as a
warning via `pcap_geterr`) just falls back to inspecting every packet in
software rather than aborting capture. Payload and app-layer filters can
never be expressed in BPF and always run in software.

A packet the parser cannot summarize at all (`parser_parse_packet_with_datalink`
returning nonzero) is counted via `stats_record_parse_failure` and skipped
with `continue`, rather than aborting the whole capture as earlier versions
did; the same treatment applies to a packet reassembled from IPv4 fragments
that fails to re-parse. `stats_record_raw_packet` counts every packet
libpcap delivers regardless of parse or filter outcome, and
`stats_record_filtered_out` counts packets that parsed successfully but did
not pass the active filters, giving `--stats` a full accounting of the
raw-seen -> parsed -> filtered -> displayed funnel.

At the end of a run, `capture_start` also queries `pcap_stats` for live
captures only (it is not meaningful for savefiles) and folds IPv4 fragment
table memory usage into `PacketStats` via `stats_apply_ipv4_fragment_table`,
alongside the existing flow-table snapshot.

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
ClientHello metadata. It is not a full TCP stack: no retransmission timers,
congestion control, or window scaling. Sequence math uses serial-number
arithmetic so it stays correct across a 32-bit wraparound. Out-of-order data is
held in a small bounded pending store (at most 8 segments, sharing the
direction's byte cap); overlaps are trimmed by keeping already-accepted bytes
and appending only new tail data. Every gap, overlap, and retransmission is
counted per direction and rolled up into flow-table-level lifetime totals as
flows leave the table, so counts survive eviction (`flow_table_snapshot_stats`
in `flow.h`).

FIN and RST are tracked for every TCP segment in a flow — including
zero-payload segments (bare ACK/FIN/RST) and segments arriving after the flow
has already been classified — which previously went unobserved because
capture only fed payload-bearing, not-yet-classified segments into
`tcp_reassembly_process_segment`. A flow counts as closed once either
direction has seen RST or both directions have seen FIN
(`flow_is_closed`), and closed flows are evicted proactively
(`flow_table_evict_closed`) instead of waiting for `--flow-timeout`. Once a
flow's app metadata is classified, its stream and pending-segment buffers are
released immediately (`flow_release_reassembly_buffers` /
`tcp_reassembly_direction_release_buffers`) since nothing reads them again;
FIN/RST tracking (`tcp_reassembly_track_flags`) keeps working with no buffer
allocated. A flow's first captured segment becomes its sequencing baseline
regardless of whether SYN was seen, so flows discovered mid-stream (capture
started after the connection was already in progress) classify normally from
whatever point capture began.

Eviction happens three ways, each counted separately: idle timeout
(`flow_table_evict_idle`), capacity pressure evicting the least-recently-seen
flow (`evict_oldest_flow`), and proactive closed-flow cleanup
(`flow_table_evict_closed`). All three run opportunistically — triggered by a
new packet arriving for any tracked flow — plus one final closed-flow pass at
capture shutdown so flows closed by the very last packet are still counted.

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

`--protocol` (tcp/udp/icmp/arp), `--port`, and `--host` are additionally
compiled into a kernel-level BPF pre-filter by `src/capture.c` (see Capture
above) when safe to do so; this never changes filtering semantics, since
`filters_match` still re-checks every field on every displayed packet.

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

`src/stats.c` tracks displayed packet totals when `--stats` is enabled. The
per-protocol and byte counters count packets after filtering, not all raw
captured packets; `raw_packets_seen`, `packets_filtered_out`, and
`parse_failures` (updated via `stats_record_raw_packet`,
`stats_record_filtered_out`, and `stats_record_parse_failure` in
`src/capture.c`) track the funnel from "delivered by libpcap" through
"parsed", "passed filters", and "displayed" regardless of `--reassemble`.
IPv4 fragment counters track fragments seen, reassembled, expired, malformed,
and dropped due to caps, plus current/configured-maximum fragment reassembly
memory via `stats_apply_ipv4_fragment_table`. App decode counters track
displayed packet statuses for no match, incomplete input, malformed input,
truncation by configured caps, and successful decodes.

When live capture is used, `stats_apply_pcap_drops` copies `pcap_stats`
(packets received, dropped, and interface-dropped) into `PacketStats` at the
end of capture; this is skipped for offline reads, and `pcap_stats_available`
records whether the driver actually supported the query.

When `--reassemble` is used, `stats_apply_flow_table` copies one point-in-time
`flow_table_snapshot_stats` result into `PacketStats` at the end of capture,
before the flow table is torn down: flows created, flows still active at exit,
flows closed via FIN, flows closed via RST, flows evicted for idle timeout,
flows evicted for capacity pressure, retransmissions, out-of-order segments,
overlapping segments, gaps, and current/configured-maximum reassembly stream
bytes. The snapshot combines already-evicted flows' lifetime totals with the
live per-direction counters of flows still in the table, so nothing is lost to
eviction ordering.

### Benchmarks

`bench/` holds lightweight local benchmarks (`bench_parser`, `bench_app_decoder`,
`bench_filters`, `bench_reassembly`), each a fixed-iteration wall-clock loop
over one hot function with synthetic in-memory data, sharing timing helpers
from `bench/bench_common.h`. They link against the same production objects as
the unit tests (excluding `src/main.c`). `make bench` builds and runs all of
them, then runs `make clean`, mirroring `make test`. These are meant to catch
gross regressions or compare before/after changes locally, not to replace
proper profiling.

### Fuzzing

`fuzz/` holds libFuzzer-compatible harnesses for the parser (`fuzz_parser.c`,
selecting a datalink type from the first input byte), DNS (`fuzz_dns.c`,
selecting among raw UDP, TCP-framed, and mDNS decode paths), HTTP
(`fuzz_http.c`), TLS ClientHello (`fuzz_tls.c`), app-protocol dispatch
(`fuzz_app_dispatch.c`, exercising both `app_decode_buffer` and
`app_decode_packet` with a fuzzed preferred protocol, transport, and ports),
TCP stream reassembly (`fuzz_reassembly.c`, replaying a sequence of
length-prefixed segments into one persistent `TcpReassemblyDirection` so gaps,
overlaps, and retransmissions spanning multiple segments are reachable), and
offline pcap ingestion (`fuzz_pcap_offline.c`, feeding the entire fuzz input to
libpcap as an in-memory savefile via `fmemopen`/`pcap_fopen_offline`, then
driving `pcap_next_ex` and `parser_parse_packet_with_datalink` in a bounded
loop). Every harness implements the standard
`LLVMFuzzerTestOneInput(data, size)` entry point declared once in
`fuzz/fuzz_common.h`.

Each harness object links two different ways from the same source:

- With `-fsanitize=fuzzer,address,undefined`, producing a real coverage-guided
  libFuzzer binary (`make fuzz-build`).
- With `fuzz/fuzz_standalone_main.c` instead of libFuzzer's own `main`, using
  only `-fsanitize=address,undefined`, producing a `<target>_smoke` binary
  that reads a list of files from `argv` and replays each through
  `LLVMFuzzerTestOneInput` once. This exists because not every toolchain ships
  a linked libFuzzer runtime (for example, a bare Xcode Command Line Tools
  install on macOS lacks `libclang_rt.fuzzer_osx.a`); `make fuzz-smoke` always
  works on such toolchains, while `make fuzz-build` probes for
  `-fsanitize=fuzzer` support first and degrades to a skip message rather than
  a hard failure when it is unavailable.

Neither linking mode requires root or a live network interface. The pcap
harness never opens a real capture device — `fmemopen` turns the fuzz bytes
into a `FILE *` that `pcap_fopen_offline` reads as a savefile, matching the
same offline-read code path `capture.c` uses for `--read`. The reassembly
harness calls `tcp_reassembly_process_segment` directly against one
in-process `TcpReassemblyDirection`, with no socket, flow table, or live TCP
connection involved.

A seed corpus lives under `fuzz/corpus/<target>/`, derived from the same
fixture bytes the unit tests use (`tests/fixtures/app_fixtures.h`), plus
hand-built truncated and malformed variants and a minimal two-packet `.pcap`
file for the offline-ingestion harness. `make fuzz-ci` runs a short bounded
libFuzzer session (`FUZZ_CI_SECONDS`, default 20 seconds) per target against
that corpus, matching the job CI runs. Both `fuzz-smoke` and `fuzz-ci` run
`make clean` afterward, mirroring `make test` and `make bench`; `fuzz-build`
leaves its binaries in place for interactive fuzzing beyond the bounded CI run.

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
- Conservative bounded TCP reassembly, not a full TCP stack: no retransmission
  timers, congestion control, or window scaling
- Idle-timeout and closed-flow eviction are opportunistic (triggered by new
  packet arrivals, plus one pass at capture shutdown), not wall-clock timers
- BPF pre-filtering covers only `--protocol` (tcp/udp/icmp/arp), `--port`, and
  `--host`; it is a pure optimization and never the sole enforcement of a
  filter, and compile/install failures fall back to full software filtering
- Parser failures are skipped and counted rather than aborting capture
- `pcap_stats` is only queried for live captures and only when the platform's
  libpcap driver supports it
- CI fuzzing (`make fuzz-ci`) is a brief bounded session per target (default
  20s via `FUZZ_CI_SECONDS`), a regression smoke net rather than a
  long-running continuous fuzzing campaign; `make fuzz-build` itself skips
  with a message on toolchains without a linked libFuzzer runtime
