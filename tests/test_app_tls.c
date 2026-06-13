#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_tls.h"
#include "fixtures/app_fixtures.h"

#define app_tls_decode_client_hello app_tls_decode_client_hello_white_box
#include "../src/app_tls.c"
#undef app_tls_decode_client_hello

static void test_app_tls_decode_client_hello_sni(void) {
    AppInfo info;

    assert(app_tls_decode_client_hello(TLS_CLIENT_HELLO_SNI,
                                       sizeof(TLS_CLIENT_HELLO_SNI),
                                       &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_TLS);
    assert(info.tls_record_version == 0x0303);
    assert(info.tls_handshake_type == 0x01);
    assert(info.tls_client_version == 0x0303);
    assert(strcmp(info.tls_sni, "example.com") == 0);
    assert(strcmp(info.tls_alpn, "") == 0);
}

static void test_app_tls_decode_client_hello_sni_alpn(void) {
    AppInfo info;

    assert(app_tls_decode_client_hello(TLS_CLIENT_HELLO_SNI_ALPN,
                                       sizeof(TLS_CLIENT_HELLO_SNI_ALPN),
                                       &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_TLS);
    assert(strcmp(info.tls_sni, "example.com") == 0);
    assert(strcmp(info.tls_alpn, "h2,http/1.1") == 0);
}

static void test_app_tls_decode_need_more(void) {
    AppInfo info;

    assert(app_tls_decode_client_hello(TLS_TRUNCATED,
                                       sizeof(TLS_TRUNCATED),
                                       &info) == APP_DECODE_NEED_MORE);
}

static void test_app_tls_decode_no_match_for_non_tls(void) {
    AppInfo info;

    assert(app_tls_decode_client_hello(TLS_NO_MATCH,
                                       sizeof(TLS_NO_MATCH),
                                       &info) == APP_DECODE_NO_MATCH);
}

static void test_app_tls_decode_malformed_client_hello(void) {
    AppInfo info;

    assert(app_tls_decode_client_hello(TLS_MALFORMED,
                                       sizeof(TLS_MALFORMED),
                                       &info) == APP_DECODE_MALFORMED);
}

static void test_app_tls_offset_and_copy_helpers(void) {
    static const uint8_t data[] = {1, 2, 3, 4};
    char destination[3];
    size_t offset = sizeof(data);
    size_t value24;
    uint8_t value8;

    assert(read_u8_at(data, sizeof(data), &offset, &value8) != 0);
    offset = sizeof(data) - 2;
    assert(read_u24_at(data, sizeof(data), &offset, &value24) != 0);
    copy_text(NULL, sizeof(destination), data, sizeof(data));
    copy_text(destination, 0, data, sizeof(data));
    copy_text(destination, sizeof(destination), data, sizeof(data));
    assert((unsigned char)destination[0] == 1);
    assert((unsigned char)destination[1] == 2);
}

static void test_app_tls_rejects_malformed_extensions(void) {
    static const uint8_t short_sni[] = {0};
    static const uint8_t bad_sni_length[] = {0, 4, 0, 0, 0};
    static const uint8_t zero_sni_name[] = {0, 3, 0, 0, 0};
    static const uint8_t short_alpn[] = {0};
    static const uint8_t bad_alpn_length[] = {0, 2, 3, 'h'};
    static const uint8_t zero_alpn[] = {0, 1, 0};
    static const uint8_t short_extensions[] = {0};
    static const uint8_t oversized_extensions[] = {0, 4, 0, 0};
    static const uint8_t short_extension_header[] = {0, 2, 0, 0};
    static const uint8_t malformed_sni_extension[] = {0, 4, 0, 0, 0, 1};
    static const uint8_t malformed_alpn_extension[] = {0, 4, 0, 16, 0, 1};
    AppInfo info;

    memset(&info, 0, sizeof(info));
    assert(parse_sni_extension(short_sni, sizeof(short_sni), &info) != 0);
    assert(parse_sni_extension(bad_sni_length, sizeof(bad_sni_length), &info) != 0);
    assert(parse_sni_extension(zero_sni_name, sizeof(zero_sni_name), &info) != 0);
    assert(parse_alpn_extension(short_alpn, sizeof(short_alpn), &info) != 0);
    assert(parse_alpn_extension(bad_alpn_length, sizeof(bad_alpn_length), &info) != 0);
    assert(parse_alpn_extension(zero_alpn, sizeof(zero_alpn), &info) != 0);

    assert(parse_extensions(NULL, 0, 0, &info) == 0);
    assert(parse_extensions(short_extensions, sizeof(short_extensions), 0, &info) != 0);
    assert(parse_extensions(oversized_extensions, sizeof(oversized_extensions), 0, &info) != 0);
    assert(parse_extensions(short_extension_header, sizeof(short_extension_header), 0, &info) != 0);
    assert(parse_extensions(malformed_sni_extension,
                            sizeof(malformed_sni_extension),
                            0,
                            &info) != 0);
    assert(parse_extensions(malformed_alpn_extension,
                            sizeof(malformed_alpn_extension),
                            0,
                            &info) != 0);
}

static void test_app_tls_alpn_bounds(void) {
    char destination[4] = "abc";
    char truncated[4] = "";
    static const uint8_t data[] = "long";

    assert(append_alpn(destination, sizeof(destination), data, 1) != 0);
    assert(append_alpn(truncated, sizeof(truncated), data, sizeof(data) - 1) == 0);
    assert(strcmp(truncated, "lon") == 0);
}

static void test_app_tls_rejects_malformed_client_body_vectors(void) {
    uint8_t body[64];
    AppInfo info;

    memset(body, 0, sizeof(body));
    assert(parse_client_hello_body(body, 1, &info) == APP_DECODE_MALFORMED);
    assert(parse_client_hello_body(body, 20, &info) == APP_DECODE_MALFORMED);

    body[0] = 3;
    body[1] = 3;
    body[34] = 40;
    assert(parse_client_hello_body(body, sizeof(body), &info) == APP_DECODE_MALFORMED);

    body[34] = 0;
    body[35] = 0;
    body[36] = 1;
    assert(parse_client_hello_body(body, sizeof(body), &info) == APP_DECODE_MALFORMED);

    body[36] = 2;
    body[37] = 0x13;
    body[38] = 1;
    body[39] = 0;
    assert(parse_client_hello_body(body, 40, &info) == APP_DECODE_MALFORMED);
}

static void test_app_tls_record_edge_cases(void) {
    static const uint8_t short_non_tls[] = {0x17};
    static const uint8_t bad_version[] = {0x16, 0x02, 0x00, 0, 0};
    static const uint8_t short_record[] = {0x16, 0x03, 0x03, 0, 8, 1};
    static const uint8_t tiny_record[] = {0x16, 0x03, 0x03, 0, 3, 1, 0, 0};
    static const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0, 4, 2, 0, 0, 0};
    static const uint8_t long_handshake[] = {0x16, 0x03, 0x03, 0, 4, 1, 0, 0, 1};
    AppInfo info;

    assert(app_tls_decode_client_hello(NULL, 1, &info) == APP_DECODE_NO_MATCH);
    assert(app_tls_decode_client_hello(short_non_tls, sizeof(short_non_tls), &info) ==
           APP_DECODE_NO_MATCH);
    assert(app_tls_decode_client_hello(bad_version, sizeof(bad_version), &info) ==
           APP_DECODE_NO_MATCH);
    assert(app_tls_decode_client_hello(short_record, sizeof(short_record), &info) ==
           APP_DECODE_NEED_MORE);
    assert(app_tls_decode_client_hello(tiny_record, sizeof(tiny_record), &info) ==
           APP_DECODE_MALFORMED);
    assert(app_tls_decode_client_hello(server_hello, sizeof(server_hello), &info) ==
           APP_DECODE_NO_MATCH);
    assert(app_tls_decode_client_hello(long_handshake, sizeof(long_handshake), &info) ==
           APP_DECODE_NEED_MORE);
    assert(app_tls_decode_client_hello_white_box(TLS_CLIENT_HELLO_SNI,
                                                 sizeof(TLS_CLIENT_HELLO_SNI),
                                                 &info) == APP_DECODE_OK);
}

int main(void) {
    test_app_tls_decode_client_hello_sni();
    test_app_tls_decode_client_hello_sni_alpn();
    test_app_tls_decode_need_more();
    test_app_tls_decode_no_match_for_non_tls();
    test_app_tls_decode_malformed_client_hello();
    test_app_tls_offset_and_copy_helpers();
    test_app_tls_rejects_malformed_extensions();
    test_app_tls_alpn_bounds();
    test_app_tls_rejects_malformed_client_body_vectors();
    test_app_tls_record_edge_cases();

    printf("All app TLS tests passed.\n");

    return 0;
}
