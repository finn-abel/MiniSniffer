#include <arpa/inet.h>
#include <string.h>

#include "parser.h"

#define ETHERNET_HEADER_LEN 14
#define ETHERNET_ETHERTYPE_OFFSET 12
#define ETHERTYPE_IPV4 0x0800

int parser_parse_packet(
    const unsigned char *packet,
    size_t packet_len,
    PacketInfo *info
) {
    uint16_t ether_type_network;
    uint16_t ether_type;

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
     * Ethernet EtherType lives at bytes 12-13.
     * Copy bytes out before ntohs so raw packet memory is never direct-cast.
     */
    memcpy(&ether_type_network, packet + ETHERNET_ETHERTYPE_OFFSET, sizeof(ether_type_network));
    ether_type = ntohs(ether_type_network);

    if (ether_type == ETHERTYPE_IPV4) {
        info->protocol = PROTO_IPV4;
    }

    return 0;
}
