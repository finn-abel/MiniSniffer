#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_http.h"
#include "fixtures/app_fixtures.h"

static void test_app_http_decode_request(void) {
    AppInfo info;

    assert(app_http_decode(HTTP_GET_WITH_HOST, sizeof(HTTP_GET_WITH_HOST) - 1, &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_HTTP);
    assert(strcmp(info.http_method, "GET") == 0);
    assert(strcmp(info.http_path, "/index.html") == 0);
    assert(strcmp(info.http_version, "HTTP/1.1") == 0);
    assert(strcmp(info.http_host, "example.com") == 0);
    assert(strcmp(info.http_user_agent, "MiniSnifferTest") == 0);
}

static void test_app_http_decode_response(void) {
    AppInfo info;

    assert(app_http_decode(HTTP_RESPONSE_STATUS, sizeof(HTTP_RESPONSE_STATUS) - 1, &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_HTTP);
    assert(strcmp(info.http_version, "HTTP/1.1") == 0);
    assert(info.http_status_code == 200);
    assert(strcmp(info.http_reason, "OK") == 0);
    assert(strcmp(info.http_content_type, "text/html") == 0);
}

static void test_app_http_decode_incomplete_header(void) {
    AppInfo info;

    assert(app_http_decode(HTTP_TRUNCATED_HEADERS, sizeof(HTTP_TRUNCATED_HEADERS) - 1, &info) == APP_DECODE_NEED_MORE);
}

static void test_app_http_decode_no_match(void) {
    AppInfo info;

    assert(app_http_decode(HTTP_NO_MATCH, sizeof(HTTP_NO_MATCH) - 1, &info) == APP_DECODE_NO_MATCH);
}

static void test_app_http_decode_malformed_request(void) {
    AppInfo info;

    assert(app_http_decode(HTTP_MALFORMED, sizeof(HTTP_MALFORMED) - 1, &info) == APP_DECODE_MALFORMED);
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
