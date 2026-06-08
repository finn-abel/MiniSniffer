#ifndef PARSER_H
#define PARSER_H

#include <stddef.h>

#include "common.h"

/*
 * Parses raw packet bytes into a PacketInfo summary.
 * This skeleton only records packet size and marks packets as PROTO_OTHER.
 * Returns 0 when the PacketInfo output is initialized successfully.
 */
int parser_parse_packet(
    const unsigned char *packet,
    size_t packet_len,
    PacketInfo *info
);

#endif
