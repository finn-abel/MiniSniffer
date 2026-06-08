# Protocol Notes

## Ethernet

Ethernet frames begin with a 14-byte header.

The EtherType field is stored in bytes 12 and 13 of that header.
PacketScope reads those two bytes with `memcpy`, then converts the value with
`ntohs`.

Current handling:

- `0x0800` is identified as IPv4 and passed to IPv4 parsing.
- Any non-IPv4 EtherType is reported as `OTHER`.
- Frames shorter than 14 bytes are treated as `OTHER`.

Raw packet bytes should not be direct-cast into C structs.

## IPv4

IPv4 starts immediately after the 14-byte Ethernet header.

Current handling:

- Validate version is 4.
- Compute header length with `(ip_header[0] & 0x0F) * 4`.
- Require at least the minimum 20-byte IPv4 header.
- Require the captured packet to include the full IPv4 header.
- Parse source and destination addresses with `inet_ntop`.
- Map protocol number 1 to `ICMP`.
- Map protocol number 6 to `TCP`.
- Map protocol number 17 to `UDP`.
- Leave all other protocol numbers as `OTHER`.
