#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>

#define PACKETSCOPE_MAX_PAYLOAD_PREVIEW_BYTES 256

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
 * protocol type, packet number, packet size, and a bounded payload preview.
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

    int has_payload;
    size_t payload_length;
    size_t payload_preview_length;
    unsigned char payload_preview[PACKETSCOPE_MAX_PAYLOAD_PREVIEW_BYTES];
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

/*
 * Parses a protocol name into a Protocol value.
 * Returns 0 for tcp, udp, icmp, or other.
 * Returns non-zero when text does not name a supported protocol.
 */
int protocol_from_string(const char *text, Protocol *protocol);

/*
 * Prints one readable packet summary line.
 * The line includes packet number, protocol, addresses when available, and size.
 */
void packet_info_print(const PacketInfo *info);

/*
 * Prints a bounded payload preview in hex and printable ASCII.
 * preview_limit caps how many bytes from PacketInfo's payload preview are shown.
 */
void packet_info_print_payload(const PacketInfo *info, size_t preview_limit);

#endif
