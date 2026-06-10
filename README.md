# PacketScope

PacketScope is a small C packet sniffer and network analyzer built on
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

Packet capture usually requires elevated permissions. On macOS, run PacketScope
with `sudo` or configure BPF capture permissions for your account.

## Build

```sh
make
```

This creates the `PacketScope` executable in the project root.

## Quick Start

Capture five displayed packets on the automatically selected interface:

```sh
sudo ./PacketScope --count 5
```

Capture on a specific interface:

```sh
sudo ./PacketScope --interface en0 --count 5
```

Capture TCP packets and print stats at the end:

```sh
sudo ./PacketScope --protocol tcp --count 20 --stats
```

Write displayed packets to a CSV file:

```sh
sudo ./PacketScope --count 10 --log packets.csv
```

Inspect payload previews and filter for HTTP request bytes:

```sh
sudo ./PacketScope --protocol tcp --payload --payload-bytes 80 --payload-contains "GET "
```

## Usage

```text
Usage: ./PacketScope [--help] [--interface <name>] [--count <number>]
       [--protocol <tcp|udp|icmp|other>] [--port <number>]
       [--host <ipv4>] [--payload] [--payload-bytes <number>]
       [--payload-contains <text>] [--payload-hex <hex>] [--log <file>]
       [--stats]
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
| `--payload-bytes <number>` | Set the payload preview length. Default is 64 bytes. Maximum is 256 bytes. |
| `--payload-contains <text>` | Display only packets whose captured payload preview contains the literal text. |
| `--payload-hex <hex>` | Display only packets whose captured payload preview contains the byte pattern. |
| `--log <file>` | Write displayed packets to a CSV file. |
| `--stats` | Print displayed packet totals after capture completes. |

`--count` is applied after filtering. For example, `--protocol tcp --count 10`
stops after ten displayed TCP packets, not after ten raw packets.

## Interface Selection

When `--interface` is omitted, PacketScope enumerates libpcap devices and
chooses a practical default. On macOS it prefers normal non-loopback IPv4
interfaces such as `en0` and avoids common internal or tunnel interfaces such
as `ap*`, `awdl*`, `llw*`, and `utun*`.

If automatic selection does not choose the interface you want, pass the
interface explicitly:

```sh
sudo ./PacketScope --interface en0 --count 5
```

## Filters

Filters use AND logic. When multiple filters are enabled, every enabled filter
must match before a packet is printed, logged, counted, or included in stats.

Examples:

```sh
sudo ./PacketScope --protocol tcp --count 10
sudo ./PacketScope --protocol udp --count 10
sudo ./PacketScope --protocol icmp --count 5
sudo ./PacketScope --port 443 --count 10
sudo ./PacketScope --protocol tcp --port 443 --count 10
sudo ./PacketScope --host 8.8.8.8 --count 10
sudo ./PacketScope --protocol tcp --port 443 --host 142.250.190.14 --count 10
```

Port filters apply only to packets with TCP or UDP ports. ICMP and other
packets do not match a port filter.

Payload filters inspect captured payload preview bytes. They do not require
`--payload`; use `--payload` only when you also want to print or log previews.

Text payload filter:

```sh
sudo ./PacketScope --protocol tcp --payload-contains "Host:"
```

Hex payload filter:

```sh
sudo ./PacketScope --payload-hex "47 45 54 20"
```

Hex patterns may include spaces, colons, or hyphens as separators. The example
above matches the bytes for `GET `.

## Output

PacketScope prints one line for each displayed packet. TCP and UDP packets
include ports:

```text
[001] TCP  192.168.1.25:51432 -> 142.250.190.14:443 size=54
```

Packets without ports omit them:

```text
[002] ICMP 192.168.1.25 -> 8.8.8.8 size=98
```

With `--payload`, PacketScope prints a bounded payload preview below each
displayed packet:

```text
[003] TCP  192.168.1.25:51432 -> 142.250.190.14:80 size=71
      payload length=17 preview=17
      hex: 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a 0d
      ascii: GET / HTTP/1.1...
```

Packets that cannot be parsed as Ethernet/IPv4 are displayed as `OTHER` when
they pass the active filters.

## CSV Logging

Use `--log <file>` to write displayed packets to CSV:

```sh
sudo ./PacketScope --count 25 --log packets.csv
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

## Stats

Use `--stats` to print a summary after capture completes:

```sh
sudo ./PacketScope --count 50 --stats
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
parsing, filtering, logging, stats, and basic capture validation. It also runs
`make clean` after the tests complete.

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
sudo ./PacketScope --count 5
```

### Wrong interface selected

Pass the interface explicitly:

```sh
sudo ./PacketScope --interface en0 --count 5
```

### Interface not found

If you see:

```text
Error: interface 'fake0' was not found.
```

Use an interface name available to libpcap on your machine. Common macOS names
include `en0` for Wi-Fi or Ethernet, depending on hardware and configuration.

### Invalid CLI input

PacketScope validates common input mistakes before capture starts, including
unknown options, missing option values, invalid protocols, invalid ports,
invalid IPv4 hosts, and log files that cannot be opened.

Examples:

```sh
./PacketScope --port
./PacketScope --port abc
./PacketScope --protocol fake
./PacketScope --host 999.1.1.1
./PacketScope --payload-bytes 999
./PacketScope --payload-hex abc
./PacketScope --interface fake0
./PacketScope --log /bad/path/file.csv
```

## Project Layout

```text
include/          Public headers
src/              PacketScope implementation
tests/            Unit tests
Makefile          Build, test, and clean targets
README.md         Project documentation
```

Important modules:

- `src/cli.c` parses command-line options into runtime configuration.
- `src/capture.c` selects an interface, opens libpcap, and runs capture.
- `src/parser.c` parses Ethernet/IPv4 packet metadata.
- `src/filter.c` applies protocol, port, and host filters.
- `src/logger.c` writes displayed packets to CSV.
- `src/stats.c` tracks displayed packet counters.

## Limitations

- PacketScope currently parses Ethernet IPv4 packets.
- TCP and UDP ports are parsed only when enough header bytes were captured.
- Payload inspection is bounded to the first 256 captured payload bytes.
- IPv6 packet parsing is not implemented.
- Protocol-aware application decoding is not implemented.
- Live capture behavior depends on libpcap support and local OS permissions.
