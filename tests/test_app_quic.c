#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_quic.h"
#include "fixtures/app_fixtures.h"

static void test_app_quic_decodes_initial_version_and_cids(void) {
    AppInfo info;

    assert(app_quic_decode_initial(QUIC_INITIAL_V1, sizeof(QUIC_INITIAL_V1), &info) ==
           APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_QUIC);
    assert(info.quic_version == 1);
    assert(strcmp(info.quic_dcid, "1122334455667788") == 0);
    assert(strcmp(info.quic_scid, "aabbccddeeff0102") == 0);
}

static void test_app_quic_stops_parsing_right_after_scid(void) {
    AppInfo info;

    /* 23 bytes covers flags+version+dcid+scid exactly; nothing after is read. */
    assert(app_quic_decode_initial(QUIC_INITIAL_V1, 23, &info) == APP_DECODE_OK);
    assert(strcmp(info.quic_scid, "aabbccddeeff0102") == 0);
}

static void test_app_quic_decodes_zero_length_connection_ids(void) {
    AppInfo info;

    assert(app_quic_decode_initial(QUIC_INITIAL_ZERO_LENGTH_CIDS,
                                   sizeof(QUIC_INITIAL_ZERO_LENGTH_CIDS), &info) ==
           APP_DECODE_OK);
    assert(info.quic_dcid[0] == '\0');
    assert(info.quic_scid[0] == '\0');
}

static void test_app_quic_rejects_short_header(void) {
    AppInfo info;

    assert(app_quic_decode_initial(QUIC_SHORT_HEADER, sizeof(QUIC_SHORT_HEADER), &info) ==
           APP_DECODE_NO_MATCH);
    assert(info.protocol == APP_PROTO_UNKNOWN);
}

static void test_app_quic_rejects_non_initial_long_header(void) {
    AppInfo info;

    assert(app_quic_decode_initial(QUIC_LONG_HEADER_NOT_INITIAL,
                                   sizeof(QUIC_LONG_HEADER_NOT_INITIAL), &info) ==
           APP_DECODE_NO_MATCH);
}

static void test_app_quic_rejects_version_negotiation(void) {
    AppInfo info;

    assert(app_quic_decode_initial(QUIC_VERSION_NEGOTIATION, sizeof(QUIC_VERSION_NEGOTIATION),
                                   &info) == APP_DECODE_NO_MATCH);
    assert(info.protocol == APP_PROTO_UNKNOWN);
}

static void test_app_quic_reports_need_more_for_truncated_fields(void) {
    AppInfo info;

    assert(app_quic_decode_initial(QUIC_INITIAL_V1, 1, &info) == APP_DECODE_NEED_MORE);
    assert(app_quic_decode_initial(QUIC_INITIAL_V1, 5, &info) == APP_DECODE_NEED_MORE);
    assert(app_quic_decode_initial(QUIC_INITIAL_V1, 6, &info) == APP_DECODE_NEED_MORE);
    assert(app_quic_decode_initial(QUIC_INITIAL_V1, 14, &info) == APP_DECODE_NEED_MORE);
    assert(app_quic_decode_initial(QUIC_INITIAL_V1, 15, &info) == APP_DECODE_NEED_MORE);
    assert(app_quic_decode_initial(QUIC_INITIAL_V1, 22, &info) == APP_DECODE_NEED_MORE);
}

static void test_app_quic_rejects_oversized_dcid(void) {
    static const uint8_t bytes[] = {0xc3, 0x00, 0x00, 0x00, 0x01, 21};
    AppInfo info;

    assert(app_quic_decode_initial(bytes, sizeof(bytes), &info) == APP_DECODE_MALFORMED);
    assert(info.protocol == APP_PROTO_UNKNOWN);
}

static void test_app_quic_rejects_oversized_scid(void) {
    static const uint8_t bytes[] = {0xc3, 0x00, 0x00, 0x00, 0x01, 0x00, 21};
    AppInfo info;

    assert(app_quic_decode_initial(bytes, sizeof(bytes), &info) == APP_DECODE_MALFORMED);
    assert(info.protocol == APP_PROTO_UNKNOWN);
}

static void test_app_quic_rejects_null_and_empty_input(void) {
    AppInfo info;

    assert(app_quic_decode_initial(NULL, 0, &info) == APP_DECODE_NO_MATCH);
    assert(info.protocol == APP_PROTO_UNKNOWN);
    assert(app_quic_decode_initial((const uint8_t *)"", 0, &info) == APP_DECODE_NO_MATCH);
}

int main(void) {
    test_app_quic_decodes_initial_version_and_cids();
    test_app_quic_stops_parsing_right_after_scid();
    test_app_quic_decodes_zero_length_connection_ids();
    test_app_quic_rejects_short_header();
    test_app_quic_rejects_non_initial_long_header();
    test_app_quic_rejects_version_negotiation();
    test_app_quic_reports_need_more_for_truncated_fields();
    test_app_quic_rejects_oversized_dcid();
    test_app_quic_rejects_oversized_scid();
    test_app_quic_rejects_null_and_empty_input();

    printf("All app QUIC tests passed.\n");

    return 0;
}
