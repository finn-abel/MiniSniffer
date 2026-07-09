#ifndef PARSER_H
#define PARSER_H

#include <stddef.h>

#include "common.h"

/*
 * Parses raw packet bytes into a PacketInfo summary using an Ethernet link
 * layer. Kept as a compatibility wrapper for tests and older callers.
 * Returns 0 when the PacketInfo output is initialized successfully.
 */
int parser_parse_packet(const unsigned char *packet, size_t packet_len, PacketInfo *info);

/*
 * Parses raw packet bytes into a PacketInfo summary for a supported libpcap
 * datalink type. The link-layer decoder selects the network-layer offset before
 * IPv4/IPv6 parsing extracts transport metadata and payload previews.
 */
int parser_parse_packet_with_datalink(const unsigned char *packet, size_t packet_len,
                                      int datalink_type, PacketInfo *info);

/*
 * Returns non-zero when MiniSniffer can parse packets from the datalink type.
 */
int parser_supports_datalink(int datalink_type);

#endif
