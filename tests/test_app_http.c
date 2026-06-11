#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_http.h"

static void test_app_http_decode_request(void) {
    const uint8_t payload[] =
        "GET /index.html HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: PacketScopeTest\r\n"
        "\r\n"
        "ignored body";
    AppInfo info;

    assert(app_http_decode(payload, sizeof(payload) - 1, &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_HTTP);
    assert(strcmp(info.http_method, "GET") == 0);
    assert(strcmp(info.http_path, "/index.html") == 0);
    assert(strcmp(info.http_version, "HTTP/1.1") == 0);
    assert(strcmp(info.http_host, "example.com") == 0);
    assert(strcmp(info.http_user_agent, "PacketScopeTest") == 0);
}

static void test_app_http_decode_response(void) {
    const uint8_t payload[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "\r\n";
    AppInfo info;

    assert(app_http_decode(payload, sizeof(payload) - 1, &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_HTTP);
    assert(strcmp(info.http_version, "HTTP/1.1") == 0);
    assert(info.http_status_code == 200);
    assert(strcmp(info.http_reason, "OK") == 0);
    assert(strcmp(info.http_content_type, "text/html") == 0);
}

static void test_app_http_decode_incomplete_header(void) {
    const uint8_t payload[] = "GET / HTTP/1.1\r\nHost: example.com\r\n";
    AppInfo info;

    assert(app_http_decode(payload, sizeof(payload) - 1, &info) == APP_DECODE_NEED_MORE);
}

static void test_app_http_decode_no_match(void) {
    const uint8_t payload[] = "SSH-2.0-test\r\n";
    AppInfo info;

    assert(app_http_decode(payload, sizeof(payload) - 1, &info) == APP_DECODE_NO_MATCH);
}

static void test_app_http_decode_malformed_request(void) {
    const uint8_t payload[] = "GET / nope\r\n\r\n";
    AppInfo info;

    assert(app_http_decode(payload, sizeof(payload) - 1, &info) == APP_DECODE_MALFORMED);
    assert(info.protocol == APP_PROTO_UNKNOWN);
}

int main(void) {
    test_app_http_decode_request();
    test_app_http_decode_response();
    test_app_http_decode_incomplete_header();
    test_app_http_decode_no_match();
    test_app_http_decode_malformed_request();

    printf("All app HTTP tests passed.\n");

    return 0;
}
