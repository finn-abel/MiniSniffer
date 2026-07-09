#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <string.h>

#include "config.h"
#include "parser.h"

#define ETHERNET_HEADER_LEN 14
#define ETHERNET_ETHERTYPE_OFFSET 12
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86dd
#define IPV4_MIN_HEADER_LEN 20
#define IPV4_VERSION 4
#define IPV6_HEADER_LEN 40
#define IPV6_VERSION 6
#define IPV4_PROTOCOL_ICMP 1
#define IPV4_PROTOCOL_TCP 6
#define IPV4_PROTOCOL_UDP 17
#define IPV6_PROTOCOL_ICMPV6 58
#define TCP_MIN_HEADER_LEN 20
#define UDP_HEADER_LEN 8
#define ICMP_HEADER_LEN 8
#define IPV4_FRAGMENT_OFFSET_MASK 0x1fff
#define IPV4_MORE_FRAGMENTS 0x2000
#define LINUX_SLL_HEADER_LEN 16
#define LINUX_SLL2_HEADER_LEN 20
#define NULL_LOOPBACK_HEADER_LEN 4

typedef enum { NETWORK_UNKNOWN = 0, NETWORK_IPV4, NETWORK_IPV6 } NetworkLayer;

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
 * Reads a four-byte network-order integer without assuming packet alignment.
 */
static uint32_t read_u32_network(const unsigned char *bytes) {
    uint32_t value;

    memcpy(&value, bytes, sizeof(value));
    return ntohl(value);
}

/*
 * Maps the IPv4 protocol number into MiniSniffer's shared protocol enum.
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

static void set_ip_protocol(unsigned char protocol_number, PacketInfo *info) {
    if (protocol_number == IPV4_PROTOCOL_ICMP || protocol_number == IPV6_PROTOCOL_ICMPV6) {
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
static void parse_tcp_ports(const unsigned char *packet, size_t packet_len, size_t tcp_offset,
                            PacketInfo *info) {
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
 * TCP sequence and flags are needed only by flow reassembly. They stay in
 * PacketInfo as raw TCP metadata, separate from application decoding.
 */
static void parse_tcp_sequence_and_flags(const unsigned char *packet, size_t packet_len,
                                         size_t tcp_offset, PacketInfo *info) {
    const unsigned char *tcp_header;

    if (packet_len < tcp_offset + TCP_MIN_HEADER_LEN) {
        return;
    }

    tcp_header = packet + tcp_offset;
    info->tcp_sequence = read_u32_network(tcp_header + 4);
    info->tcp_flags = (uint8_t)(tcp_header[13] & 0x3f);
    info->has_tcp_sequence = 1;
}

/*
 * UDP ports are the first four bytes of the fixed eight-byte UDP header.
 * If the capture is truncated before the full UDP header, leave ports unset.
 */
static void parse_udp_ports(const unsigned char *packet, size_t packet_len, size_t udp_offset,
                            PacketInfo *info) {
    const unsigned char *udp_header;

    if (packet_len < udp_offset + UDP_HEADER_LEN) {
        return;
    }

    udp_header = packet + udp_offset;
    if (read_u16_network(udp_header + 4) < UDP_HEADER_LEN) {
        return;
    }
    info->src_port = read_u16_network(udp_header);
    info->dst_port = read_u16_network(udp_header + 2);
    info->has_ports = 1;
}

static void parse_payload(const unsigned char *packet, size_t packet_len, size_t payload_offset,
                          PacketInfo *info) {
    size_t available;

    if (packet_len <= payload_offset) {
        return;
    }

    /*
     * payload_capture_length records how much captured data remains after
     * headers. payload_decode_length is the larger bounded view for app
     * decoders. payload_preview stores only the smaller display/logging prefix.
     */
    available = packet_len - payload_offset;
    info->has_payload = available > 0;
    info->payload = packet + payload_offset;
    info->payload_capture_length = available;
    info->payload_decode_length = available;
    if (info->payload_decode_length > MINISNIFFER_DEFAULT_PAYLOAD_DECODE_BYTES) {
        info->payload_decode_length = MINISNIFFER_DEFAULT_PAYLOAD_DECODE_BYTES;
    }
    info->payload_preview_length = available;
    if (info->payload_preview_length > MINISNIFFER_MAX_PAYLOAD_PREVIEW_BYTES) {
        info->payload_preview_length = MINISNIFFER_MAX_PAYLOAD_PREVIEW_BYTES;
    }

    memcpy(info->payload_preview, info->payload, info->payload_preview_length);
}

/*
 * TCP has a variable-length header.
 * The data offset field in byte 12 tells us where payload bytes begin.
 */
static void parse_tcp_payload(const unsigned char *packet, size_t packet_len, size_t tcp_offset,
                              PacketInfo *info) {
    const unsigned char *tcp_header;
    size_t tcp_header_len;

    if (packet_len < tcp_offset + TCP_MIN_HEADER_LEN) {
        return;
    }

    tcp_header = packet + tcp_offset;
    /* TCP data offset is stored in 32-bit words in the high nibble. */
    tcp_header_len = (size_t)(tcp_header[12] >> 4) * 4;
    if (tcp_header_len < TCP_MIN_HEADER_LEN) {
        return;
    }
    if (packet_len < tcp_offset + tcp_header_len) {
        return;
    }

    parse_payload(packet, packet_len, tcp_offset + tcp_header_len, info);
}

/*
 * UDP has a fixed eight-byte header, so payload begins immediately after it.
 */
static void parse_udp_payload(const unsigned char *packet, size_t packet_len, size_t udp_offset,
                              PacketInfo *info) {
    uint16_t udp_length;

    if (packet_len < udp_offset + UDP_HEADER_LEN) {
        return;
    }

    udp_length = read_u16_network(packet + udp_offset + 4);
    if (udp_length < UDP_HEADER_LEN) {
        return;
    }
    if ((size_t)udp_length > packet_len - udp_offset) {
        return;
    }
    if ((size_t)udp_length < packet_len - udp_offset) {
        packet_len = udp_offset + (size_t)udp_length;
    }

    parse_payload(packet, packet_len, udp_offset + UDP_HEADER_LEN, info);
}

/*
 * ICMP's common header is eight bytes for the packet types MiniSniffer displays.
 * Anything captured after that is treated as ICMP payload preview data.
 */
static void parse_icmp_payload(const unsigned char *packet, size_t packet_len, size_t icmp_offset,
                               PacketInfo *info) {
    if (packet_len < icmp_offset + ICMP_HEADER_LEN) {
        return;
    }

    parse_payload(packet, packet_len, icmp_offset + ICMP_HEADER_LEN, info);
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

static void initialize_packet_info(const unsigned char *packet, size_t packet_len,
                                   PacketInfo *info) {
    (void)packet;

    memset(info, 0, sizeof(*info));
    info->size = packet_len;
    info->protocol = PROTO_OTHER;
    info->src_ip[0] = '\0';
    info->dst_ip[0] = '\0';
}

static int parse_ipv4_packet(const unsigned char *packet, size_t packet_len, size_t ip_offset,
                             PacketInfo *info) {
    const unsigned char *ip_header;
    uint16_t ip_total_length;
    uint16_t fragment_field;
    size_t captured_ip_length;
    size_t parsed_packet_len;
    size_t ip_header_len;
    unsigned char ip_version;
    if (packet_len < ip_offset + IPV4_MIN_HEADER_LEN) {
        return 0;
    }

    /*
     * The first byte contains both version and IHL, so validate both before
     * reading any deeper IPv4 fields.
     */
    ip_header = packet + ip_offset;
    ip_version = (unsigned char)(ip_header[0] >> 4);
    ip_header_len = (size_t)(ip_header[0] & 0x0F) * 4;

    if (ip_version != IPV4_VERSION || ip_header_len < IPV4_MIN_HEADER_LEN) {
        return 0;
    }
    if (packet_len < ip_offset + ip_header_len) {
        return 0;
    }

    ip_total_length = read_u16_network(ip_header + 2);
    if (ip_total_length < ip_header_len) {
        return 0;
    }
    captured_ip_length = packet_len - ip_offset;
    parsed_packet_len =
        ip_offset + (captured_ip_length < (size_t)ip_total_length ? captured_ip_length
                                                                  : (size_t)ip_total_length);

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
     * Payload previews are derived from each transport header's own length.
     */
    set_ipv4_protocol(ip_header[9], info);
    clear_transport_ports(info);

    /*
     * Transport headers in fragmented datagrams are not safe to interpret
     * without IPv4 reassembly. Even the first fragment may not contain a full
     * transport payload, so leave only coarse IP protocol metadata populated.
     */
    fragment_field = read_u16_network(ip_header + 6);
    if ((fragment_field & (IPV4_FRAGMENT_OFFSET_MASK | IPV4_MORE_FRAGMENTS)) != 0) {
        return 0;
    }

    if (info->protocol == PROTO_TCP) {
        parse_tcp_ports(packet, parsed_packet_len, ip_offset + ip_header_len, info);
        parse_tcp_sequence_and_flags(packet, parsed_packet_len, ip_offset + ip_header_len, info);
        parse_tcp_payload(packet, parsed_packet_len, ip_offset + ip_header_len, info);
    } else if (info->protocol == PROTO_UDP) {
        parse_udp_ports(packet, parsed_packet_len, ip_offset + ip_header_len, info);
        parse_udp_payload(packet, parsed_packet_len, ip_offset + ip_header_len, info);
    } else if (info->protocol == PROTO_ICMP) {
        clear_transport_ports(info);
        parse_icmp_payload(packet, parsed_packet_len, ip_offset + ip_header_len, info);
    }

    return 0;
}

static int parse_ipv6_packet(const unsigned char *packet, size_t packet_len, size_t ip_offset,
                             PacketInfo *info) {
    const unsigned char *ip_header;
    size_t captured_ip_length;
    size_t parsed_packet_len;
    uint16_t payload_length;
    unsigned char next_header;
    unsigned char ip_version;
    size_t transport_offset;

    if (packet_len < ip_offset + IPV6_HEADER_LEN) {
        return 0;
    }

    ip_header = packet + ip_offset;
    ip_version = (unsigned char)(ip_header[0] >> 4);
    if (ip_version != IPV6_VERSION) {
        return 0;
    }

    payload_length = read_u16_network(ip_header + 4);
    next_header = ip_header[6];
    captured_ip_length = packet_len - ip_offset;
    parsed_packet_len = ip_offset + (captured_ip_length < IPV6_HEADER_LEN + (size_t)payload_length
                                         ? captured_ip_length
                                         : IPV6_HEADER_LEN + (size_t)payload_length);

    if (inet_ntop(AF_INET6, ip_header + 8, info->src_ip, sizeof(info->src_ip)) == NULL) {
        return 1;
    }
    if (inet_ntop(AF_INET6, ip_header + 24, info->dst_ip, sizeof(info->dst_ip)) == NULL) {
        return 1;
    }

    set_ip_protocol(next_header, info);
    clear_transport_ports(info);
    transport_offset = ip_offset + IPV6_HEADER_LEN;

    if (info->protocol == PROTO_TCP) {
        parse_tcp_ports(packet, parsed_packet_len, transport_offset, info);
        parse_tcp_sequence_and_flags(packet, parsed_packet_len, transport_offset, info);
        parse_tcp_payload(packet, parsed_packet_len, transport_offset, info);
    } else if (info->protocol == PROTO_UDP) {
        parse_udp_ports(packet, parsed_packet_len, transport_offset, info);
        parse_udp_payload(packet, parsed_packet_len, transport_offset, info);
    } else if (info->protocol == PROTO_ICMP) {
        parse_icmp_payload(packet, parsed_packet_len, transport_offset, info);
    }

    return 0;
}

static NetworkLayer network_from_ethertype(uint16_t ethertype) {
    if (ethertype == ETHERTYPE_IPV4) {
        return NETWORK_IPV4;
    }
    if (ethertype == ETHERTYPE_IPV6) {
        return NETWORK_IPV6;
    }

    return NETWORK_UNKNOWN;
}

static uint32_t read_u32_little(const unsigned char *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static uint32_t read_u32_big(const unsigned char *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) |
           (uint32_t)bytes[3];
}

static NetworkLayer network_from_null_family(const unsigned char *bytes) {
    uint32_t little = read_u32_little(bytes);
    uint32_t big = read_u32_big(bytes);

    if (little == AF_INET || big == AF_INET) {
        return NETWORK_IPV4;
    }
    if (little == AF_INET6 || big == AF_INET6 || little == 24 || big == 24 || little == 28 ||
        big == 28 || little == 30 || big == 30) {
        return NETWORK_IPV6;
    }

    return NETWORK_UNKNOWN;
}

static NetworkLayer infer_raw_ip_network(const unsigned char *packet, size_t packet_len) {
    unsigned char version;

    if (packet == NULL || packet_len == 0) {
        return NETWORK_UNKNOWN;
    }

    version = (unsigned char)(packet[0] >> 4);
    if (version == IPV4_VERSION) {
        return NETWORK_IPV4;
    }
    if (version == IPV6_VERSION) {
        return NETWORK_IPV6;
    }

    return NETWORK_UNKNOWN;
}

static int select_network_layer(const unsigned char *packet, size_t packet_len, int datalink_type,
                                size_t *ip_offset, NetworkLayer *network) {
    uint16_t ethertype;

    if (ip_offset == NULL || network == NULL) {
        return 1;
    }
    *ip_offset = 0;
    *network = NETWORK_UNKNOWN;

    if (packet == NULL || packet_len == 0) {
        return 0;
    }

    if (datalink_type == DLT_EN10MB) {
        if (packet_len < ETHERNET_HEADER_LEN) {
            return 0;
        }
        ethertype = read_u16_network(packet + ETHERNET_ETHERTYPE_OFFSET);
        *ip_offset = ETHERNET_HEADER_LEN;
        *network = network_from_ethertype(ethertype);
        return 0;
    }

    if (datalink_type == DLT_RAW) {
        *network = infer_raw_ip_network(packet, packet_len);
        return 0;
    }

#ifdef DLT_IPV4
    if (datalink_type == DLT_IPV4) {
        *network = NETWORK_IPV4;
        return 0;
    }
#endif

#ifdef DLT_IPV6
    if (datalink_type == DLT_IPV6) {
        *network = NETWORK_IPV6;
        return 0;
    }
#endif

    if (datalink_type == DLT_NULL || datalink_type == DLT_LOOP) {
        if (packet_len < NULL_LOOPBACK_HEADER_LEN) {
            return 0;
        }
        *ip_offset = NULL_LOOPBACK_HEADER_LEN;
        *network = network_from_null_family(packet);
        return 0;
    }

#ifdef DLT_LINUX_SLL
    if (datalink_type == DLT_LINUX_SLL) {
        if (packet_len < LINUX_SLL_HEADER_LEN) {
            return 0;
        }
        ethertype = read_u16_network(packet + 14);
        *ip_offset = LINUX_SLL_HEADER_LEN;
        *network = network_from_ethertype(ethertype);
        return 0;
    }
#endif

#ifdef DLT_LINUX_SLL2
    if (datalink_type == DLT_LINUX_SLL2) {
        if (packet_len < LINUX_SLL2_HEADER_LEN) {
            return 0;
        }
        ethertype = read_u16_network(packet);
        *ip_offset = LINUX_SLL2_HEADER_LEN;
        *network = network_from_ethertype(ethertype);
        return 0;
    }
#endif

    return 0;
}

int parser_supports_datalink(int datalink_type) {
    if (datalink_type == DLT_EN10MB || datalink_type == DLT_RAW || datalink_type == DLT_NULL ||
        datalink_type == DLT_LOOP) {
        return 1;
    }
#ifdef DLT_IPV4
    if (datalink_type == DLT_IPV4) {
        return 1;
    }
#endif
#ifdef DLT_IPV6
    if (datalink_type == DLT_IPV6) {
        return 1;
    }
#endif
#ifdef DLT_LINUX_SLL
    if (datalink_type == DLT_LINUX_SLL) {
        return 1;
    }
#endif
#ifdef DLT_LINUX_SLL2
    if (datalink_type == DLT_LINUX_SLL2) {
        return 1;
    }
#endif

    return 0;
}

int parser_parse_packet_with_datalink(const unsigned char *packet, size_t packet_len,
                                      int datalink_type, PacketInfo *info) {
    size_t ip_offset;
    NetworkLayer network;

    if (info == NULL) {
        return 1;
    }
    initialize_packet_info(packet, packet_len, info);

    if (packet_len == 0) {
        return 0;
    }
    if (packet == NULL) {
        return 1;
    }

    if (select_network_layer(packet, packet_len, datalink_type, &ip_offset, &network) != 0) {
        return 1;
    }
    if (network == NETWORK_IPV4) {
        return parse_ipv4_packet(packet, packet_len, ip_offset, info);
    }
    if (network == NETWORK_IPV6) {
        return parse_ipv6_packet(packet, packet_len, ip_offset, info);
    }

    return 0;
}

int parser_parse_packet(const unsigned char *packet, size_t packet_len, PacketInfo *info) {
    return parser_parse_packet_with_datalink(packet, packet_len, DLT_EN10MB, info);
}
