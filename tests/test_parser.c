#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "parser.h"

static void test_parser_parse_packet_initializes_basic_info(void) {
    const unsigned char packet[] = {0x00, 0x01, 0x02};
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.size == sizeof(packet));
    assert(info.protocol == PROTO_OTHER);
    assert(strcmp(info.src_ip, "") == 0);
    assert(strcmp(info.dst_ip, "") == 0);
    assert(info.has_ports == 0);
    assert(info.app.protocol == APP_PROTO_UNKNOWN);
}

static void test_parser_parse_packet_marks_short_frame_as_other(void) {
    const unsigned char packet[] = {0x00, 0x01, 0x02};
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.protocol == PROTO_OTHER);
    assert(info.size == sizeof(packet));
}

static void test_parser_parse_packet_parses_tcp_ipv4_metadata(void) {
    const unsigned char packet[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x19,
        0x8e, 0xfa, 0xbe, 0x0e,
        0xc8, 0xe8, 0x01, 0xbb,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.protocol == PROTO_TCP);
    assert(strcmp(info.src_ip, "192.168.1.25") == 0);
    assert(strcmp(info.dst_ip, "142.250.190.14") == 0);
    assert(info.size == sizeof(packet));
    assert(info.has_ports == 1);
    assert(info.src_port == 51432);
    assert(info.dst_port == 443);
    assert(info.has_tcp_sequence == 1);
    assert(info.tcp_sequence == 0);
    assert(info.tcp_flags == 0);
}

static void test_parser_parse_packet_extracts_tcp_payload_preview(void) {
    const unsigned char packet[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x2d,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x19,
        0x8e, 0xfa, 0xbe, 0x0e,
        0xc8, 0xe8, 0x01, 0xbb,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        'G', 'E', 'T', ' ', '/'
    };
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.protocol == PROTO_TCP);
    assert(info.has_payload == 1);
    assert(info.payload == packet + sizeof(packet) - 5);
    assert(info.payload_capture_length == 5);
    assert(info.payload_decode_length == 5);
    assert(info.payload_preview_length == 5);
    assert(memcmp(info.payload_preview, "GET /", 5) == 0);
}

static void test_parser_parse_packet_skips_tcp_ports_when_header_is_short(void) {
    const unsigned char packet[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x1c,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x19,
        0x8e, 0xfa, 0xbe, 0x0e,
        0xc8, 0xe8
    };
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.protocol == PROTO_TCP);
    assert(info.has_ports == 0);
}

static void test_parser_parse_packet_parses_udp_ipv4_metadata(void) {
    const unsigned char packet[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x1c,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x19,
        0xe0, 0x00, 0x00, 0xfb,
        0x14, 0xe9, 0x14, 0xe9,
        0x00, 0x08, 0x00, 0x00
    };
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.protocol == PROTO_UDP);
    assert(strcmp(info.src_ip, "192.168.1.25") == 0);
    assert(strcmp(info.dst_ip, "224.0.0.251") == 0);
    assert(info.has_ports == 1);
    assert(info.src_port == 5353);
    assert(info.dst_port == 5353);
}

static void test_parser_parse_packet_skips_udp_ports_when_header_is_short(void) {
    const unsigned char packet[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x14,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x19,
        0xe0, 0x00, 0x00, 0xfb,
        0x14, 0xe9
    };
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.protocol == PROTO_UDP);
    assert(info.has_ports == 0);
}

static void test_parser_parse_packet_parses_icmp_ipv4_metadata(void) {
    const unsigned char packet[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x14,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x01, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x19,
        0x08, 0x08, 0x08, 0x08
    };
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.protocol == PROTO_ICMP);
    assert(strcmp(info.src_ip, "192.168.1.25") == 0);
    assert(strcmp(info.dst_ip, "8.8.8.8") == 0);
    assert(info.has_ports == 0);
    assert(info.src_port == 0);
    assert(info.dst_port == 0);
}

static void test_parser_parse_packet_rejects_invalid_ipv4_version(void) {
    const unsigned char packet[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x08, 0x00,
        0x65, 0x00, 0x00, 0x14,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x19,
        0x8e, 0xfa, 0xbe, 0x0e
    };
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.protocol == PROTO_OTHER);
    assert(strcmp(info.src_ip, "") == 0);
    assert(strcmp(info.dst_ip, "") == 0);
}

static void test_parser_parse_packet_rejects_short_ipv4_header(void) {
    const unsigned char packet[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x08, 0x00,
        0x44, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x19,
        0x8e, 0xfa, 0xbe, 0x0e
    };
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.protocol == PROTO_OTHER);
}

static void test_parser_parse_packet_marks_non_ipv4_ethertype_as_other(void) {
    const unsigned char packet[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x86, 0xdd
    };
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.protocol == PROTO_OTHER);
    assert(info.size == sizeof(packet));
}

static void test_parser_honors_ipv4_total_length_over_ethernet_padding(void) {
    const unsigned char packet[] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x28, 0, 0, 0, 0, 0x40, 0x06, 0, 0,
        10, 0, 0, 1, 10, 0, 0, 2,
        0x13, 0x88, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0,
        0x50, 0x00, 0, 0, 0, 0, 0, 0,
        'E', 'V', 'I', 'L'
    };
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.has_ports == 1);
    assert(info.has_payload == 0);
}

static void test_parser_does_not_decode_fragmented_transport_headers(void) {
    const unsigned char packet[] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x28, 0, 1, 0x20, 0, 0x40, 0x06, 0, 0,
        10, 0, 0, 1, 10, 0, 0, 2,
        0x13, 0x88, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0,
        0x50, 0x00, 0, 0, 0, 0, 0, 0
    };
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.protocol == PROTO_TCP);
    assert(info.has_ports == 0);
    assert(info.has_payload == 0);
}

static void test_parser_honors_udp_payload_length(void) {
    const unsigned char packet[] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x20, 0, 0, 0, 0, 0x40, 0x11, 0, 0,
        10, 0, 0, 1, 10, 0, 0, 2,
        0x13, 0x88, 0x00, 0x35, 0x00, 0x0a, 0, 0,
        'O', 'K', 'N', 'O'
    };
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.has_ports == 1);
    assert(info.payload_capture_length == 2);
    assert(memcmp(info.payload, "OK", 2) == 0);
}

static void test_parser_rejects_invalid_udp_length(void) {
    const unsigned char packet[] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 0x40, 0x11, 0, 0,
        10, 0, 0, 1, 10, 0, 0, 2,
        0x13, 0x88, 0x00, 0x35, 0x00, 0x07, 0, 0
    };
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.protocol == PROTO_UDP);
    assert(info.has_ports == 0);
    assert(info.has_payload == 0);
}

static void test_parser_parse_packet_rejects_null_info(void) {
    const unsigned char packet[] = {0x00};

    assert(parser_parse_packet(packet, sizeof(packet), NULL) != 0);
}

static void test_parser_handles_empty_null_and_unknown_protocol(void) {
    const unsigned char unknown_protocol[] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 99, 0, 0,
        10, 0, 0, 1, 10, 0, 0, 2
    };
    PacketInfo info;

    assert(parser_parse_packet(NULL, 0, &info) == 0);
    assert(info.size == 0);
    assert(parser_parse_packet(NULL, 1, &info) != 0);
    assert(parser_parse_packet(unknown_protocol, sizeof(unknown_protocol), &info) == 0);
    assert(info.protocol == PROTO_OTHER);
    assert(strcmp(info.src_ip, "10.0.0.1") == 0);
}

static void test_parser_caps_large_payload_views(void) {
    unsigned char packet[14 + 20 + 20 + 2200];
    PacketInfo info;
    size_t ip = 14;
    size_t tcp = 34;
    uint16_t total_length = 20 + 20 + 2200;

    memset(packet, 0, sizeof(packet));
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[ip] = 0x45;
    packet[ip + 2] = (unsigned char)(total_length >> 8);
    packet[ip + 3] = (unsigned char)total_length;
    packet[ip + 8] = 64;
    packet[ip + 9] = 6;
    packet[ip + 12] = 10;
    packet[ip + 15] = 1;
    packet[ip + 16] = 10;
    packet[ip + 19] = 2;
    packet[tcp + 1] = 80;
    packet[tcp + 3] = 80;
    packet[tcp + 12] = 0x50;
    memset(packet + tcp + 20, 'A', 2200);

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.payload_capture_length == 2200);
    assert(info.payload_decode_length == MINISNIFFER_DEFAULT_PAYLOAD_DECODE_BYTES);
    assert(info.payload_preview_length == MINISNIFFER_MAX_PAYLOAD_PREVIEW_BYTES);
}

static void test_parser_rejects_invalid_transport_header_lengths(void) {
    unsigned char tcp_packet[] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0,
        10, 0, 0, 1, 10, 0, 0, 2,
        0x13, 0x88, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0,
        0x40, 0, 0, 0, 0, 0, 0, 0
    };
    unsigned char udp_packet[] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0,
        10, 0, 0, 1, 10, 0, 0, 2,
        0x13, 0x88, 0, 53, 0, 20, 0, 0
    };
    PacketInfo info;

    assert(parser_parse_packet(tcp_packet, sizeof(tcp_packet), &info) == 0);
    assert(info.has_payload == 0);
    tcp_packet[46] = 0xf0;
    assert(parser_parse_packet(tcp_packet, sizeof(tcp_packet), &info) == 0);
    assert(info.has_payload == 0);

    assert(parser_parse_packet(udp_packet, sizeof(udp_packet), &info) == 0);
    assert(info.has_ports == 1);
    assert(info.has_payload == 0);
}

static void test_parser_extracts_icmp_payload(void) {
    const unsigned char packet[] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0, 0, 30, 0, 0, 0, 0, 64, 1, 0, 0,
        10, 0, 0, 1, 10, 0, 0, 2,
        8, 0, 0, 0, 0, 1, 0, 1,
        'O', 'K'
    };
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.protocol == PROTO_ICMP);
    assert(info.payload_capture_length == 2);
    assert(memcmp(info.payload, "OK", 2) == 0);
}

static void test_parser_rejects_invalid_ipv4_lengths(void) {
    unsigned char packet[] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x46, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0,
        10, 0, 0, 1, 10, 0, 0, 2
    };
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.protocol == PROTO_OTHER);
    packet[14] = 0x45;
    packet[17] = 19;
    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.protocol == PROTO_OTHER);
}

int main(void) {
    test_parser_parse_packet_initializes_basic_info();
    test_parser_parse_packet_marks_short_frame_as_other();
    test_parser_parse_packet_parses_tcp_ipv4_metadata();
    test_parser_parse_packet_extracts_tcp_payload_preview();
    test_parser_parse_packet_skips_tcp_ports_when_header_is_short();
    test_parser_parse_packet_parses_udp_ipv4_metadata();
    test_parser_parse_packet_skips_udp_ports_when_header_is_short();
    test_parser_parse_packet_parses_icmp_ipv4_metadata();
    test_parser_parse_packet_rejects_invalid_ipv4_version();
    test_parser_parse_packet_rejects_short_ipv4_header();
    test_parser_parse_packet_marks_non_ipv4_ethertype_as_other();
    test_parser_honors_ipv4_total_length_over_ethernet_padding();
    test_parser_does_not_decode_fragmented_transport_headers();
    test_parser_honors_udp_payload_length();
    test_parser_rejects_invalid_udp_length();
    test_parser_parse_packet_rejects_null_info();
    test_parser_handles_empty_null_and_unknown_protocol();
    test_parser_caps_large_payload_views();
    test_parser_rejects_invalid_transport_header_lengths();
    test_parser_extracts_icmp_payload();
    test_parser_rejects_invalid_ipv4_lengths();

    printf("All parser tests passed.\n");

    return 0;
}
