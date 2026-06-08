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
}

static void test_parser_parse_packet_marks_short_frame_as_other(void) {
    const unsigned char packet[] = {0x00, 0x01, 0x02};
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.protocol == PROTO_OTHER);
    assert(info.size == sizeof(packet));
}

static void test_parser_parse_packet_detects_ipv4_ethertype(void) {
    const unsigned char packet[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x08, 0x00
    };
    PacketInfo info;

    assert(parser_parse_packet(packet, sizeof(packet), &info) == 0);
    assert(info.protocol == PROTO_IPV4);
    assert(info.size == sizeof(packet));
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
    test_parser_parse_packet_detects_ipv4_ethertype();
    test_parser_parse_packet_marks_non_ipv4_ethertype_as_other();
    test_parser_parse_packet_rejects_null_info();

    printf("All parser tests passed.\n");

    return 0;
}
