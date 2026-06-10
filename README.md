# PacketScope

PacketScope is a C-based packet sniffer/network analyzer.

## Dependencies

Install libpcap before building:

```sh
brew install libpcap
```

Packet capture may require sudo.

## Build

```sh
make
```

## Run

```sh
sudo ./PacketScope --count 5
sudo ./PacketScope --interface en0 --count 5
```

`--count` counts displayed packets after filters are applied.

## Filters

Filters use AND logic when combined. Every enabled filter must match before a
packet is displayed.

Examples:

```sh
sudo ./PacketScope --protocol tcp --count 10
sudo ./PacketScope --protocol udp --count 10
sudo ./PacketScope --protocol icmp --count 5
sudo ./PacketScope --port 443 --count 10
sudo ./PacketScope --protocol tcp --port 443 --count 10
sudo ./PacketScope --port 53 --count 10
sudo ./PacketScope --host 8.8.8.8 --count 10
sudo ./PacketScope --host 1.1.1.1 --count 10
sudo ./PacketScope --protocol tcp --port 443 --host 142.250.190.14 --count 10
```
