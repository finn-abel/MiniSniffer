#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_dns.h"

static const uint8_t dns_query[] = {
    0x12, 0x34, 0x01, 0x00,
    0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x03, 'w', 'w', 'w',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,
    0x00, 0x01
};

static void test_app_dns_decode_udp_query(void) {
    AppInfo info;

    assert(app_dns_decode_udp(dns_query, sizeof(dns_query), &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_DNS);
    assert(info.dns_transaction_id == 0x1234);
    assert(info.dns_is_response == 0);
    assert(info.dns_opcode == 0);
    assert(info.dns_rcode == 0);
    assert(info.dns_question_count == 1);
    assert(strcmp(info.dns_query_name, "www.example.com") == 0);
    assert(info.dns_query_type == 1);
    assert(info.dns_query_class == 1);
}

static void test_app_dns_decode_response_with_compressed_question(void) {
    const uint8_t response[] = {
        0x12, 0x34, 0x81, 0x80,
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x03, 'w', 'w', 'w',
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        0xc0, 0x0c,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x3c,
        0x00, 0x04,
        0x5d, 0xb8, 0xd8, 0x22
    };
    AppInfo info;

    assert(app_dns_decode_message(response, sizeof(response), &info) == APP_DECODE_OK);
    assert(info.dns_is_response == 1);
    assert(strcmp(info.dns_query_name, "www.example.com") == 0);
}

static void test_app_dns_decode_tcp_frame(void) {
    uint8_t frame[sizeof(dns_query) + 2];
    AppInfo info;

    frame[0] = 0x00;
    frame[1] = (uint8_t)sizeof(dns_query);
    memcpy(frame + 2, dns_query, sizeof(dns_query));

    assert(app_dns_decode_tcp_frame(frame, sizeof(frame), &info) == APP_DECODE_OK);
    assert(strcmp(info.dns_query_name, "www.example.com") == 0);
}

static void test_app_dns_decode_tcp_frame_need_more(void) {
    const uint8_t frame[] = {0x00, 0x20, 0x12, 0x34};
    AppInfo info;

    assert(app_dns_decode_tcp_frame(frame, sizeof(frame), &info) == APP_DECODE_NEED_MORE);
}

static void test_app_dns_decode_malformed_pointer_loop(void) {
    const uint8_t payload[] = {
        0x12, 0x34, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xc0, 0x0c,
        0x00, 0x01,
        0x00, 0x01
    };
    AppInfo info;

    assert(app_dns_decode_message(payload, sizeof(payload), &info) == APP_DECODE_MALFORMED);
    assert(info.protocol == APP_PROTO_UNKNOWN);
}

int main(void) {
    test_app_dns_decode_udp_query();
    test_app_dns_decode_response_with_compressed_question();
    test_app_dns_decode_tcp_frame();
    test_app_dns_decode_tcp_frame_need_more();
    test_app_dns_decode_malformed_pointer_loop();

    printf("All app DNS tests passed.\n");

    return 0;
}
