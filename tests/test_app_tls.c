#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_tls.h"
#include "fixtures/app_fixtures.h"

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

int main(void) {
    test_app_tls_decode_client_hello_sni();
    test_app_tls_decode_client_hello_sni_alpn();
    test_app_tls_decode_need_more();
    test_app_tls_decode_no_match_for_non_tls();
    test_app_tls_decode_malformed_client_hello();

    printf("All app TLS tests passed.\n");

    return 0;
}
