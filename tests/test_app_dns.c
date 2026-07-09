#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_dns.h"
#include "fixtures/app_fixtures.h"

#define app_dns_decode_message app_dns_decode_message_white_box
#define app_dns_decode_tcp_frame app_dns_decode_tcp_frame_white_box
#define app_dns_decode_udp app_dns_decode_udp_white_box
#define app_dns_decode_mdns_message app_dns_decode_mdns_message_white_box
#define app_dns_decode_mdns_udp app_dns_decode_mdns_udp_white_box
#include "../src/app_dns.c"
#undef app_dns_decode_message
#undef app_dns_decode_tcp_frame
#undef app_dns_decode_udp
#undef app_dns_decode_mdns_message
#undef app_dns_decode_mdns_udp

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

    assert(app_dns_decode_message(DNS_COMPRESSED_RESPONSE, sizeof(DNS_COMPRESSED_RESPONSE),
                                  &info) == APP_DECODE_OK);
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

    assert(app_dns_decode_tcp_frame(DNS_TCP_TRUNCATED_FRAME, sizeof(DNS_TCP_TRUNCATED_FRAME),
                                    &info) == APP_DECODE_NEED_MORE);
}

static void test_app_dns_decode_malformed_pointer_loop(void) {
    AppInfo info;

    assert(app_dns_decode_message(DNS_MALFORMED_POINTER_LOOP, sizeof(DNS_MALFORMED_POINTER_LOOP),
                                  &info) == APP_DECODE_MALFORMED);
    assert(info.protocol == APP_PROTO_UNKNOWN);
}

static void test_app_dns_decode_truncated_message(void) {
    AppInfo info;

    assert(app_dns_decode_message(DNS_TRUNCATED, sizeof(DNS_TRUNCATED), &info) ==
           APP_DECODE_NEED_MORE);
}

static void test_app_dns_decode_no_match(void) {
    AppInfo info;

    assert(app_dns_decode_message(NULL, 0, &info) == APP_DECODE_NO_MATCH);
}

static void test_app_dns_name_parser_rejects_invalid_inputs(void) {
    static const uint8_t root[] = {0};
    static const uint8_t bad_pointer[] = {0xc0, 0xff};
    static const uint8_t bad_label_bits[] = {0x80, 0};
    static const uint8_t truncated_label[] = {3, 'a'};
    static const uint8_t no_terminator[] = {1, 'a'};
    static const uint8_t two_labels[] = {1, 'a', 1, 'b', 0};
    char output[8];
    size_t offset = 0;

    assert(parse_dns_name(NULL, 1, &offset, output, sizeof(output)) != 0);
    assert(parse_dns_name(root, sizeof(root), NULL, output, sizeof(output)) != 0);
    assert(parse_dns_name(root, sizeof(root), &offset, NULL, sizeof(output)) != 0);
    assert(parse_dns_name(root, sizeof(root), &offset, output, 0) != 0);
    offset = sizeof(root);
    assert(parse_dns_name(root, sizeof(root), &offset, output, sizeof(output)) != 0);

    offset = 0;
    assert(parse_dns_name(root, sizeof(root), &offset, output, 1) != 0);
    offset = 0;
    assert(parse_dns_name(root, sizeof(root), &offset, output, 2) == 0);
    assert(strcmp(output, ".") == 0);
    offset = 0;
    assert(parse_dns_name(bad_pointer, sizeof(bad_pointer), &offset, output, sizeof(output)) != 0);
    offset = 0;
    assert(parse_dns_name(bad_label_bits, sizeof(bad_label_bits), &offset, output,
                          sizeof(output)) != 0);
    offset = 0;
    assert(parse_dns_name(truncated_label, sizeof(truncated_label), &offset, output,
                          sizeof(output)) != 0);
    offset = 0;
    assert(parse_dns_name(no_terminator, sizeof(no_terminator), &offset, output, sizeof(output)) !=
           0);
    offset = 0;
    assert(parse_dns_name(two_labels, sizeof(two_labels), &offset, output, 3) != 0);
    offset = 0;
    assert(parse_dns_name(two_labels, sizeof(two_labels), &offset, output, 2) != 0);
}

static void test_app_dns_rejects_implausible_and_truncated_questions(void) {
    uint8_t implausible[12] = {0};
    uint8_t truncated_question[14] = {0};
    AppInfo info;

    implausible[4] = 0;
    implausible[5] = 65;
    assert(app_dns_decode_message(implausible, sizeof(implausible), &info) == APP_DECODE_NO_MATCH);

    truncated_question[5] = 1;
    truncated_question[12] = 0;
    assert(app_dns_decode_message(truncated_question, sizeof(truncated_question), &info) ==
           APP_DECODE_MALFORMED);
    assert(info.protocol == APP_PROTO_UNKNOWN);
}

static void test_app_dns_decode_mdns_udp_query(void) {
    AppInfo info;

    assert(app_dns_decode_mdns_udp(DNS_A_QUERY, sizeof(DNS_A_QUERY), &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_MDNS);
    assert(info.dns_transaction_id == 0x1234);
    assert(strcmp(info.dns_query_name, "www.example.com") == 0);
    assert(info.dns_query_type == 1);
}

static void test_app_dns_decode_mdns_message_shares_dns_parser_failures(void) {
    AppInfo info;

    assert(app_dns_decode_mdns_message(DNS_MALFORMED_POINTER_LOOP,
                                       sizeof(DNS_MALFORMED_POINTER_LOOP),
                                       &info) == APP_DECODE_MALFORMED);
    assert(info.protocol == APP_PROTO_UNKNOWN);

    assert(app_dns_decode_mdns_message(DNS_TRUNCATED, sizeof(DNS_TRUNCATED), &info) ==
           APP_DECODE_NEED_MORE);
}

static void test_app_dns_tcp_frame_edge_cases(void) {
    static const uint8_t one_byte[] = {0};
    static const uint8_t zero_frame[] = {0, 0};
    AppInfo info;

    assert(app_dns_decode_tcp_frame(NULL, 1, &info) == APP_DECODE_NO_MATCH);
    assert(app_dns_decode_tcp_frame(one_byte, sizeof(one_byte), &info) == APP_DECODE_NEED_MORE);
    assert(app_dns_decode_tcp_frame(zero_frame, sizeof(zero_frame), &info) == APP_DECODE_MALFORMED);
    assert(app_dns_decode_udp_white_box(DNS_A_QUERY, sizeof(DNS_A_QUERY), &info) == APP_DECODE_OK);
}

int main(void) {
    test_app_dns_decode_udp_query();
    test_app_dns_decode_response_with_compressed_question();
    test_app_dns_decode_tcp_frame();
    test_app_dns_decode_tcp_frame_need_more();
    test_app_dns_decode_malformed_pointer_loop();
    test_app_dns_decode_truncated_message();
    test_app_dns_decode_no_match();
    test_app_dns_name_parser_rejects_invalid_inputs();
    test_app_dns_rejects_implausible_and_truncated_questions();
    test_app_dns_decode_mdns_udp_query();
    test_app_dns_decode_mdns_message_shares_dns_parser_failures();
    test_app_dns_tcp_frame_edge_cases();

    printf("All app DNS tests passed.\n");

    return 0;
}
