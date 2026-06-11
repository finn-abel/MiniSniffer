#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_dns.h"
#include "fixtures/app_fixtures.h"

static void test_app_dns_decode_udp_query(void) {
    AppInfo info;

    assert(app_dns_decode_udp(DNS_A_QUERY, sizeof(DNS_A_QUERY), &info) == APP_DECODE_OK);
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
    AppInfo info;

    assert(app_dns_decode_message(DNS_COMPRESSED_RESPONSE, sizeof(DNS_COMPRESSED_RESPONSE), &info) == APP_DECODE_OK);
    assert(info.dns_is_response == 1);
    assert(strcmp(info.dns_query_name, "www.example.com") == 0);
}

static void test_app_dns_decode_tcp_frame(void) {
    uint8_t frame[sizeof(DNS_A_QUERY) + 2];
    AppInfo info;

    frame[0] = 0x00;
    frame[1] = (uint8_t)sizeof(DNS_A_QUERY);
    memcpy(frame + 2, DNS_A_QUERY, sizeof(DNS_A_QUERY));

    assert(app_dns_decode_tcp_frame(frame, sizeof(frame), &info) == APP_DECODE_OK);
    assert(strcmp(info.dns_query_name, "www.example.com") == 0);
}

static void test_app_dns_decode_tcp_frame_need_more(void) {
    AppInfo info;

    assert(app_dns_decode_tcp_frame(DNS_TCP_TRUNCATED_FRAME, sizeof(DNS_TCP_TRUNCATED_FRAME), &info) == APP_DECODE_NEED_MORE);
}

static void test_app_dns_decode_malformed_pointer_loop(void) {
    AppInfo info;

    assert(app_dns_decode_message(DNS_MALFORMED_POINTER_LOOP, sizeof(DNS_MALFORMED_POINTER_LOOP), &info) == APP_DECODE_MALFORMED);
    assert(info.protocol == APP_PROTO_UNKNOWN);
}

static void test_app_dns_decode_truncated_message(void) {
    AppInfo info;

    assert(app_dns_decode_message(DNS_TRUNCATED, sizeof(DNS_TRUNCATED), &info) == APP_DECODE_NEED_MORE);
}

static void test_app_dns_decode_no_match(void) {
    AppInfo info;

    assert(app_dns_decode_message(NULL, 0, &info) == APP_DECODE_NO_MATCH);
}

int main(void) {
    test_app_dns_decode_udp_query();
    test_app_dns_decode_response_with_compressed_question();
    test_app_dns_decode_tcp_frame();
    test_app_dns_decode_tcp_frame_need_more();
    test_app_dns_decode_malformed_pointer_loop();
    test_app_dns_decode_truncated_message();
    test_app_dns_decode_no_match();

    printf("All app DNS tests passed.\n");

    return 0;
}
