
#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_OTHER
} Protocol;

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

typedef struct {
    uint32_t total_packets;
    uint32_t tcp_packets;
    uint32_t udp_packets;
    uint32_t icmp_packets;
    uint32_t other_packets;
    size_t total_bytes;
} PacketStats;

const char *protocol_to_string(Protocol protocol);

#endif
