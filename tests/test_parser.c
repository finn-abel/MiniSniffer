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

static void test_parser_parse_packet_rejects_null_info(void) {
    const unsigned char packet[] = {0x00};

    assert(parser_parse_packet(packet, sizeof(packet), NULL) != 0);
}

int main(void) {
    test_parser_parse_packet_initializes_basic_info();
    test_parser_parse_packet_rejects_null_info();

    printf("All parser tests passed.\n");

    return 0;
}
