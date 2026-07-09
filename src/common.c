#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "common.h"

const char *protocol_to_string(Protocol protocol) {
    /* Keep display strings centralized so capture summaries stay consistent. */
    switch (protocol) {
    case PROTO_TCP:
        return "TCP";
    case PROTO_UDP:
        return "UDP";
    case PROTO_ICMP:
        return "ICMP";
    case PROTO_OTHER:
    default:
        return "OTHER";
    }
}

static const char *packet_protocol_display(const PacketInfo *info) {
    if (info != NULL && info->protocol == PROTO_ICMP && info->ip_version == 6) {
        return "ICMPv6";
    }

    return protocol_to_string(info == NULL ? PROTO_OTHER : info->protocol);
}

static void print_endpoint_with_port(const char *ip, uint16_t port) {
    if (ip != NULL && strchr(ip, ':') != NULL) {
        printf("[%s]:%u", ip, (unsigned int)port);
        return;
    }

    printf("%s:%u", ip == NULL ? "" : ip, (unsigned int)port);
}

int protocol_from_string(const char *text, Protocol *protocol) {
    /* Reject null inputs before comparing against supported protocol names. */
    if (text == NULL || protocol == NULL) {
        return 1;
    }

    if (strcmp(text, "tcp") == 0) {
        *protocol = PROTO_TCP;
        return 0;
    }
    if (strcmp(text, "udp") == 0) {
        *protocol = PROTO_UDP;
        return 0;
    }
    if (strcmp(text, "icmp") == 0) {
        *protocol = PROTO_ICMP;
        return 0;
    }
    if (strcmp(text, "other") == 0) {
        *protocol = PROTO_OTHER;
        return 0;
    }

    return 1;
}

const char *app_decode_status_to_string(AppDecodeStatus status) {
    switch (status) {
    case APP_DECODE_STATUS_NO_MATCH:
        return "no_match";
    case APP_DECODE_STATUS_NEED_MORE:
        return "need_more";
    case APP_DECODE_STATUS_MALFORMED:
        return "malformed";
    case APP_DECODE_STATUS_TRUNCATED:
        return "truncated";
    case APP_DECODE_STATUS_DECODED:
        return "decoded";
    case APP_DECODE_STATUS_NOT_RUN:
    default:
        return "not_run";
    }
}

void packet_info_print(const PacketInfo *info) {
    if (info == NULL) {
        return;
    }

    /* Include addresses when IPv4 parsing has filled both endpoint strings. */
    if (info->src_ip[0] != '\0' && info->dst_ip[0] != '\0') {
        if (info->has_ports != 0) {
            printf("[%03u] %-6s ", info->packet_number, packet_protocol_display(info));
            print_endpoint_with_port(info->src_ip, info->src_port);
            printf(" -> ");
            print_endpoint_with_port(info->dst_ip, info->dst_port);
            printf(" size=%zu\n", info->size);
            return;
        }

        printf("[%03u] %-6s %s -> %s size=%zu", info->packet_number,
               packet_protocol_display(info), info->src_ip, info->dst_ip, info->size);
        if (info->has_icmp != 0) {
            printf(" type=%u code=%u", (unsigned int)info->icmp_type,
                   (unsigned int)info->icmp_code);
        }
        printf("\n");
        return;
    }

    printf("[%03u] %-6s size=%zu\n", info->packet_number, packet_protocol_display(info),
           info->size);
}

void packet_info_print_payload(const PacketInfo *info, size_t preview_limit) {
    size_t limit;
    size_t i;

    if (info == NULL || info->has_payload == 0) {
        return;
    }

    limit = info->payload_preview_length;
    if (limit > preview_limit) {
        limit = preview_limit;
    }

    printf("      payload length=%zu preview=%zu", info->payload_capture_length, limit);
    if (info->payload_capture_length > limit) {
        printf("/%zu", info->payload_capture_length);
    }
    printf("\n");

    printf("      hex: ");
    for (i = 0; i < limit; i++) {
        printf("%02x", info->payload_preview[i]);
        if (i + 1 < limit) {
            printf(" ");
        }
    }
    printf("\n");

    printf("      ascii: ");
    for (i = 0; i < limit; i++) {
        unsigned char value = info->payload_preview[i];
        printf("%c", isprint(value) ? value : '.');
    }
    printf("\n");
}
