#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "common.h"

static void test_protocol_to_string_returns_known_values(void) {
    assert(strcmp(protocol_to_string(PROTO_TCP), "TCP") == 0);
    assert(strcmp(protocol_to_string(PROTO_UDP), "UDP") == 0);
    assert(strcmp(protocol_to_string(PROTO_ICMP), "ICMP") == 0);
    assert(strcmp(protocol_to_string(PROTO_ARP), "ARP") == 0);
    assert(strcmp(protocol_to_string(PROTO_OTHER), "OTHER") == 0);
}

static void test_protocol_from_string_accepts_known_values(void) {
    Protocol protocol;

    assert(protocol_from_string("tcp", &protocol) == 0);
    assert(protocol == PROTO_TCP);
    assert(protocol_from_string("udp", &protocol) == 0);
    assert(protocol == PROTO_UDP);
    assert(protocol_from_string("icmp", &protocol) == 0);
    assert(protocol == PROTO_ICMP);
    assert(protocol_from_string("arp", &protocol) == 0);
    assert(protocol == PROTO_ARP);
    assert(protocol_from_string("other", &protocol) == 0);
    assert(protocol == PROTO_OTHER);
}

static void test_protocol_from_string_rejects_unknown_values(void) {
    Protocol protocol = PROTO_OTHER;

    assert(protocol_from_string("fake", &protocol) != 0);
    assert(protocol_from_string(NULL, &protocol) != 0);
    assert(protocol_from_string("tcp", NULL) != 0);
}

static void test_packet_info_print_accepts_null_info(void) {
    packet_info_print(NULL);
}

static void test_packet_info_print_handles_all_summary_shapes(void) {
    PacketInfo info;

    memset(&info, 0, sizeof(info));
    info.packet_number = 7;
    info.protocol = PROTO_TCP;
    info.size = 64;
    packet_info_print(&info);

    snprintf(info.src_ip, sizeof(info.src_ip), "10.0.0.1");
    snprintf(info.dst_ip, sizeof(info.dst_ip), "10.0.0.2");
    packet_info_print(&info);

    info.has_ports = 1;
    info.src_port = 1234;
    info.dst_port = 443;
    packet_info_print(&info);
}

static void test_packet_info_print_payload_handles_bounds(void) {
    PacketInfo info;

    memset(&info, 0, sizeof(info));
    packet_info_print_payload(NULL, 4);
    packet_info_print_payload(&info, 4);

    info.has_payload = 1;
    info.payload_capture_length = 4;
    info.payload_preview_length = 4;
    info.payload_preview[0] = 'A';
    info.payload_preview[1] = 0x00;
    info.payload_preview[2] = ' ';
    info.payload_preview[3] = 0xff;
    packet_info_print_payload(&info, 2);
    packet_info_print_payload(&info, 8);
}

int main(void) {
    test_protocol_to_string_returns_known_values();
    test_protocol_from_string_accepts_known_values();
    test_protocol_from_string_rejects_unknown_values();
    test_packet_info_print_accepts_null_info();
    test_packet_info_print_handles_all_summary_shapes();
    test_packet_info_print_payload_handles_bounds();

    printf("All common tests passed.\n");

    return 0;
}
