#ifndef PARSER_H
#define PARSER_H

#include <stddef.h>

#include "common.h"

/*
 * Parses raw packet bytes into a PacketInfo summary.
 * Recognizes Ethernet IPv4 packets and extracts protocol, endpoint addresses,
 * TCP/UDP ports, a direct payload pointer, payload_capture_length,
 * payload_decode_length, and payload_preview_length when present.
 * Returns 0 when the PacketInfo output is initialized successfully.
 */
int parser_parse_packet(
    const unsigned char *packet,
    size_t packet_len,
    PacketInfo *info
);

#endif
