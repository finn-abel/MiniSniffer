#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_http.h"
#include "fixtures/app_fixtures.h"

#define app_http_decode app_http_decode_white_box
#include "../src/app_http.c"
#undef app_http_decode

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

static void test_app_http_handles_partial_and_empty_inputs(void) {
    AppInfo info;

    assert(app_http_decode(NULL, 1, &info) == APP_DECODE_NO_MATCH);
    assert(app_http_decode((const uint8_t *)"", 0, NULL) == APP_DECODE_NO_MATCH);
    assert(app_http_decode((const uint8_t *)"P", 1, &info) == APP_DECODE_NEED_MORE);
    assert(find_crlf((const uint8_t *)"abc", (const uint8_t *)"abc" + 3) == NULL);
}

static void test_app_http_copy_and_header_helpers(void) {
    char destination[4];
    static const uint8_t spaced[] = "  abc  ";

    copy_trimmed(NULL, sizeof(destination), spaced, sizeof(spaced) - 1);
    copy_trimmed(destination, 0, spaced, sizeof(spaced) - 1);
    copy_trimmed(destination, sizeof(destination), spaced, sizeof(spaced) - 1);
    assert(strcmp(destination, "abc") == 0);
    assert(header_name_equals((const uint8_t *)"HOST", 4, "Host"));
    assert(!header_name_equals((const uint8_t *)"Hosts", 5, "Host"));
    assert(!header_name_equals((const uint8_t *)"Hast", 4, "Host"));
}

static void test_app_http_rejects_malformed_request_lines(void) {
    AppInfo info;

    memset(&info, 0, sizeof(info));
    assert(parse_request_line((const uint8_t *)"GET", 3, &info) != 0);
    assert(parse_request_line((const uint8_t *)" GET / HTTP/1.1", 15, &info) != 0);
    assert(parse_request_line((const uint8_t *)"GET /", 5, &info) != 0);
    assert(parse_request_line((const uint8_t *)"GET  HTTP/1.1", 13, &info) != 0);
    assert(parse_request_line((const uint8_t *)"GET / BAD", 9, &info) != 0);
}

static void test_app_http_rejects_malformed_status_lines(void) {
    AppInfo info;
    static const uint8_t short_status[] = "HTTP/1.1 20";
    static const uint8_t no_space[] = "HTTP/12345678";
    static const uint8_t bad_digits[] = "HTTP/1.1 ABC Nope";
    static const uint8_t malformed_response[] = "HTTP/1.1 ABC Nope\r\n\r\n";

    memset(&info, 0, sizeof(info));
    assert(parse_status_line(short_status, sizeof(short_status) - 1, &info) != 0);
    assert(parse_status_line(no_space, sizeof(no_space) - 1, &info) != 0);
    assert(parse_status_line(bad_digits, sizeof(bad_digits) - 1, &info) != 0);
    assert(app_http_decode(malformed_response, sizeof(malformed_response) - 1, &info) ==
           APP_DECODE_MALFORMED);
}

static void test_app_http_parses_trimmed_truncated_headers(void) {
    static const uint8_t request[] =
        "POST / HTTP/1.1\r\n"
        "Host:   very-long-host-name.example.com   \r\n"
        "X-Other: ignored\r\n"
        "\r\n";
    AppInfo info;

    assert(app_http_decode_white_box(request, sizeof(request) - 1, &info) == APP_DECODE_OK);
    assert(strcmp(info.http_host, "very-long-host-name.example.com") == 0);
    parse_headers((const uint8_t *)"broken", (const uint8_t *)"broken" + 6, &info);
}

int main(void) {
    test_app_http_decode_request();
    test_app_http_decode_response();
    test_app_http_decode_incomplete_header();
    test_app_http_decode_no_match();
    test_app_http_decode_malformed_request();
    test_app_http_handles_partial_and_empty_inputs();
    test_app_http_copy_and_header_helpers();
    test_app_http_rejects_malformed_request_lines();
    test_app_http_rejects_malformed_status_lines();
    test_app_http_parses_trimmed_truncated_headers();

    printf("All app HTTP tests passed.\n");

    return 0;
}
