#include <assert.h>
#include <stdio.h>
#include <string.h>

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
        0x45, 0x00, 0x00, 0x14,
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
        0x45, 0x00, 0x00, 0x1d,
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
        0x45, 0x00, 0x00, 0x14,
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
        0x45, 0x00, 0x00, 0x14,
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

static void test_parser_parse_packet_rejects_null_info(void) {
    const unsigned char packet[] = {0x00};

    assert(parser_parse_packet(packet, sizeof(packet), NULL) != 0);
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
    test_parser_parse_packet_rejects_null_info();

    printf("All parser tests passed.\n");

    return 0;
}
