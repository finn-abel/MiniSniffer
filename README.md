# MiniSniffer

MiniSniffer is a small C packet sniffer and network analyzer built on libpcap.
It captures live packets (or reads pcap files), parses common IPv4/IPv6
link-layer formats, applies filters, prints readable summaries, decodes
application metadata, and can log to CSV/JSON or report capture statistics.

It is built for learning, local diagnostics, and authorized network
observation. It does **not** decrypt traffic, inject or modify packets, or do
anything for MITM, credential capture, evasion, or use on networks you do not
own or have permission to inspect.

## Highlights

- Live capture with libpcap, or offline replay with `--read` / capture-to-pcap with `--write`
- IPv4/IPv6 parsing for TCP, UDP, ICMP/ICMPv6, ARP, and more
- Protocol, port, host, payload (text/hex), and application-metadata filters
- Kernel-level BPF pre-filtering (optimization only; `--no-bpf` to disable)
- App metadata decoding: HTTP, DNS/mDNS, TLS ClientHello, DHCP, and conservative QUIC Initial
- Bounded IPv4 fragment and TCP stream reassembly
- Human-readable, JSON Lines (`--json`), and CSV (`--log`) output, plus `--stats`

## Requirements

- A C11 compiler, `make`, and libpcap

| Platform | Install |
| --- | --- |
| macOS (Homebrew) | `brew install libpcap pkg-config` |
| Debian / Ubuntu | `sudo apt-get install build-essential libpcap-dev pkg-config` |
| Fedora / RHEL | `sudo dnf install gcc make libpcap-devel pkgconf-pkg-config` |
| Arch | `sudo pacman -S base-devel libpcap pkgconf` |

Live capture needs elevated permissions: run with `sudo`, or on Linux grant the
binary capabilities instead of root:

```sh
sudo setcap cap_net_raw,cap_net_admin+eip ./MiniSniffer
```

## Build

```sh
make            # builds ./MiniSniffer
make install    # installs binary, man page, and shell completions (honors PREFIX/DESTDIR)
make WITH_LIBIDN2=1   # optional: enables IDNA domain matching (--domain-match idna)
```

The build uses `pkg-config` for libpcap when available and falls back to
`-lpcap`. Override `CC`, `CFLAGS`, `PKG_CONFIG`, or `LDLIBS` on the `make` line
if your toolchain needs it. A Homebrew formula is kept in-tree at
`packaging/homebrew/minisniffer.rb` for local/`--HEAD` installs (not yet published to a tap).

## Quick Start

```sh
sudo ./MiniSniffer --count 5                                  # 5 packets, default interface
sudo ./MiniSniffer --interface en0 --count 5                  # specific interface
sudo ./MiniSniffer --protocol tcp --count 20 --stats          # filter + summary stats
sudo ./MiniSniffer --count 10 --log packets.csv               # log to CSV
sudo ./MiniSniffer --protocol tcp --payload --payload-contains "GET "   # payload filter
./MiniSniffer --read capture.pcap --protocol tcp --count 10   # offline, no sudo needed
./MiniSniffer --list-interfaces                               # see available interfaces
```

Run `./MiniSniffer --help` for the full option list, or `man ./man/minisniffer.1`
for detailed documentation of every flag.

## Filters

Filters use **AND** logic: when multiple are enabled, every one must match
before a packet is displayed, logged, counted, or included in stats. `--count`
is applied *after* filtering.

```sh
sudo ./MiniSniffer --protocol tcp --port 443 --host 142.250.190.14 --count 10
sudo ./MiniSniffer --payload-hex "47 45 54 20"                          # matches "GET "
sudo ./MiniSniffer --decode-app --app dns --dns-query example.com --dns-type A
sudo ./MiniSniffer --decode-app --app tls --tls-sni example.com --tls-alpn h2
```

`--protocol`, `--port`, and `--host` are compiled into a kernel-level BPF filter
as a pure optimization; every displayed packet is still re-checked in software,
and `--no-bpf` disables it. Payload and app-layer filters always run in
software. Application filters require `--decode-app`; add `--reassemble` to
classify flows across multiple TCP segments. HTTP Host, DNS query, and TLS SNI
filters use normalized (case-insensitive) domain matching by default —
`--domain-match exact` or `idna` change this.

## Output

One line per displayed packet:

```text
[001] TCP  192.168.1.25:51432 -> 142.250.190.14:443 size=54
[002] ICMP 192.168.1.25 -> 8.8.8.8 size=98
```

`--payload` adds a bounded hex/ASCII preview, `--decode-app` prints decoded
application metadata (with a status of `decoded`, `need_more`, `malformed`,
`truncated`, or `no_match`), and `--json` emits JSON Lines instead of text.
`--log <file>` writes CSV. Application metadata is escaped before output, and
CSV cells neutralize spreadsheet formula characters. See the man page for the
JSON object shape and full CSV schema.

## Development

```sh
make test        # unit tests
make check       # tests + sanitizers + format-check + static-check
make bench       # lightweight local benchmarks
make fuzz-smoke  # replay fuzz corpora under ASan/UBSan
make coverage    # LLVM line + branch coverage
make clean
```

`make check` skips format/static checks with a message when clang-format /
clang-tidy / cppcheck are unavailable. Fuzzing harnesses live under `fuzz/`
(libFuzzer, with a standalone smoke driver for toolchains without a linked
libFuzzer runtime). GitHub Actions workflows are included as manually triggered
(`workflow_dispatch`) quality gates.

## Project Layout

```text
include/       Public headers            fuzz/         Fuzzing harnesses + corpus
src/           Implementation            man/          Man page (minisniffer.1)
tests/         Unit tests                completions/  Bash, zsh, fish completions
bench/         Local benchmarks          packaging/    Packaging metadata
docs/          Architecture docs         Makefile      Build/test/bench/fuzz/install
```

## Documentation

- [Architecture](docs/architecture.md) — module design, reassembly model, and internal caps
- Man page: `man ./man/minisniffer.1`
- Full option reference: `./MiniSniffer --help`

## License

See [LICENSE](LICENSE).
```

