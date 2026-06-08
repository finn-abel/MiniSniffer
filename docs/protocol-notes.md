# Protocol Notes

## Ethernet

Ethernet frames begin with a 14-byte header.

The EtherType field is stored in bytes 12 and 13 of that header.
PacketScope reads those two bytes with `memcpy`, then converts the value with
`ntohs`.

Current handling:

- `0x0800` is identified as IPv4 and reported as `IPv4`.
- Any non-IPv4 EtherType is reported as `OTHER`.
- Frames shorter than 14 bytes are treated as `OTHER`.

Raw packet bytes should not be direct-cast into C structs.
