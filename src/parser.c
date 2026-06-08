#include <arpa/inet.h>
#include <string.h>

#include "parser.h"

#define ETHERNET_HEADER_LEN 14
#define ETHERNET_ETHERTYPE_OFFSET 12
#define ETHERTYPE_IPV4 0x0800
#define IPV4_MIN_HEADER_LEN 20
#define IPV4_VERSION 4
#define IPV4_PROTOCOL_ICMP 1
#define IPV4_PROTOCOL_TCP 6
#define IPV4_PROTOCOL_UDP 17
#define TCP_MIN_HEADER_LEN 20
#define UDP_HEADER_LEN 8

/*
 * Reads a two-byte network-order integer without assuming packet alignment.
 * Raw packet pointers may not be aligned enough for direct integer access.
 */
static uint16_t read_u16_network(const unsigned char *bytes) {
    uint16_t value;

    memcpy(&value, bytes, sizeof(value));
    return ntohs(value);
}

/*
 * Maps the IPv4 protocol number into PacketScope's shared protocol enum.
 * Unsupported protocol numbers intentionally collapse to PROTO_OTHER.
 */
static void set_ipv4_protocol(unsigned char protocol_number, PacketInfo *info) {
    if (protocol_number == IPV4_PROTOCOL_ICMP) {
        info->protocol = PROTO_ICMP;
    } else if (protocol_number == IPV4_PROTOCOL_TCP) {
        info->protocol = PROTO_TCP;
    } else if (protocol_number == IPV4_PROTOCOL_UDP) {
        info->protocol = PROTO_UDP;
    } else {
        info->protocol = PROTO_OTHER;
    }
}

/*
 * TCP ports are the first four bytes of the TCP header.
 * Only parse them after confirming the captured packet includes the minimum header.
 */
static void parse_tcp_ports(
    const unsigned char *packet,
    size_t packet_len,
    size_t tcp_offset,
    PacketInfo *info
) {
    const unsigned char *tcp_header;

    if (packet_len < tcp_offset + TCP_MIN_HEADER_LEN) {
        return;
    }

    tcp_header = packet + tcp_offset;
    info->src_port = read_u16_network(tcp_header);
    info->dst_port = read_u16_network(tcp_header + 2);
    info->has_ports = 1;
}

/*
 * UDP ports are the first four bytes of the fixed eight-byte UDP header.
 * If the capture is truncated before the full UDP header, leave ports unset.
 */
static void parse_udp_ports(
    const unsigned char *packet,
    size_t packet_len,
    size_t udp_offset,
    PacketInfo *info
) {
    const unsigned char *udp_header;

    if (packet_len < udp_offset + UDP_HEADER_LEN) {
        return;
    }

    udp_header = packet + udp_offset;
    info->src_port = read_u16_network(udp_header);
    info->dst_port = read_u16_network(udp_header + 2);
    info->has_ports = 1;
}

/*
 * Transport ports are opt-in metadata.
 * Clear them before parsing each packet so ICMP and OTHER never show stale ports.
 */
static void clear_transport_ports(PacketInfo *info) {
    info->src_port = 0;
    info->dst_port = 0;
    info->has_ports = 0;
}

int parser_parse_packet(
    const unsigned char *packet,
    size_t packet_len,
    PacketInfo *info
) {
    const unsigned char *ip_header;
    uint16_t ether_type_network;
    uint16_t ether_type;
    size_t ip_header_len;
    unsigned char ip_version;

    if (info == NULL) {
        return 1;
    }

    /* Start with a safe OTHER summary, then refine it as headers are recognized. */
    memset(info, 0, sizeof(*info));
    info->size = packet_len;
    info->protocol = PROTO_OTHER;
    info->src_ip[0] = '\0';
    info->dst_ip[0] = '\0';

    if (packet_len == 0) {
        return 0;
    }
    if (packet == NULL) {
        return 1;
    }
    if (packet_len < ETHERNET_HEADER_LEN) {
        return 0;
    }

    /*
     * Ethernet parsing is the first gate.
     * Ethernet EtherType lives at bytes 12-13.
     * Copy bytes out before ntohs so raw packet memory is never direct-cast.
     */
    memcpy(&ether_type_network, packet + ETHERNET_ETHERTYPE_OFFSET, sizeof(ether_type_network));
    ether_type = ntohs(ether_type_network);

    if (ether_type != ETHERTYPE_IPV4) {
        return 0;
    }

    if (packet_len < ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN) {
        return 0;
    }

    /*
     * IPv4 starts immediately after Ethernet.
     * The first byte contains both version and IHL, so validate both before
     * reading any deeper IPv4 fields.
     */
    ip_header = packet + ETHERNET_HEADER_LEN;
    ip_version = (unsigned char)(ip_header[0] >> 4);
    ip_header_len = (size_t)(ip_header[0] & 0x0F) * 4;

    if (ip_version != IPV4_VERSION || ip_header_len < IPV4_MIN_HEADER_LEN) {
        return 0;
    }
    if (packet_len < ETHERNET_HEADER_LEN + ip_header_len) {
        return 0;
    }

    /*
     * inet_ntop handles byte-order details for IPv4 address presentation.
     * The source and destination fields begin at offsets 12 and 16.
     */
    if (inet_ntop(AF_INET, ip_header + 12, info->src_ip, sizeof(info->src_ip)) == NULL) {
        return 1;
    }
    if (inet_ntop(AF_INET, ip_header + 16, info->dst_ip, sizeof(info->dst_ip)) == NULL) {
        return 1;
    }

    /*
     * Transport metadata starts after the variable-length IPv4 header.
     * ICMP has no ports, while TCP and UDP expose source and destination ports.
     */
    set_ipv4_protocol(ip_header[9], info);
    clear_transport_ports(info);
    if (info->protocol == PROTO_TCP) {
        parse_tcp_ports(packet, packet_len, ETHERNET_HEADER_LEN + ip_header_len, info);
    } else if (info->protocol == PROTO_UDP) {
        parse_udp_ports(packet, packet_len, ETHERNET_HEADER_LEN + ip_header_len, info);
    } else if (info->protocol == PROTO_ICMP) {
        clear_transport_ports(info);
    }

    return 0;
}
