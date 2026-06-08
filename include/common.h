#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>

/*
 * Protocol describes the coarse protocol category for a packet.
 * Parsers assign this value after inspecting packet headers.
 * Filters, logs, and stats use it for consistent behavior.
 */
typedef enum {
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_OTHER
} Protocol;

/*
 * PacketInfo represents one captured packet after basic parsing.
 * It stores source and destination IPv4 addresses, optional transport ports,
 * protocol type, packet number, and packet size.
 * has_ports is non-zero only when src_port and dst_port are valid.
 */
typedef struct {
    char src_ip[16];
    char dst_ip[16];

    uint16_t src_port;
    uint16_t dst_port;

    Protocol protocol;

    uint32_t packet_number;
    size_t size;

    int has_ports;
} PacketInfo;

/*
 * PacketStats stores running traffic counters.
 * It tracks the total packet count, per-protocol counts, and total bytes.
 * Stats mode and summary output will read from this struct.
 */
typedef struct {
    uint32_t total_packets;
    uint32_t tcp_packets;
    uint32_t udp_packets;
    uint32_t icmp_packets;
    uint32_t other_packets;

    size_t total_bytes;
} PacketStats;

/*
 * Converts a Protocol value into a stable display string.
 * Unknown or fallback protocol values are displayed as OTHER.
 */
const char *protocol_to_string(Protocol protocol);

#endif
