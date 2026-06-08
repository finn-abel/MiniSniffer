#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "common.h"

static void test_protocol_to_string_returns_known_values(void) {
    assert(strcmp(protocol_to_string(PROTO_TCP), "TCP") == 0);
    assert(strcmp(protocol_to_string(PROTO_UDP), "UDP") == 0);
    assert(strcmp(protocol_to_string(PROTO_ICMP), "ICMP") == 0);
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

int main(void) {
    test_protocol_to_string_returns_known_values();
    test_protocol_from_string_accepts_known_values();
    test_protocol_from_string_rejects_unknown_values();
    test_packet_info_print_accepts_null_info();

    printf("All common tests passed.\n");

    return 0;
}
