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
