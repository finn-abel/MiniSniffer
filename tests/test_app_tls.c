#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_tls.h"

static void append_u8(uint8_t *buffer, size_t *offset, uint8_t value) {
    buffer[*offset] = value;
    (*offset)++;
}

static void append_u16(uint8_t *buffer, size_t *offset, uint16_t value) {
    append_u8(buffer, offset, (uint8_t)(value >> 8));
    append_u8(buffer, offset, (uint8_t)(value & 0xff));
}

static size_t build_client_hello(uint8_t *buffer, size_t buffer_size) {
    size_t offset = 0;
    size_t i;

    (void)buffer_size;

    append_u8(buffer, &offset, 0x16);
    append_u16(buffer, &offset, 0x0303);
    append_u16(buffer, &offset, 0x0055);

    append_u8(buffer, &offset, 0x01);
    append_u8(buffer, &offset, 0x00);
    append_u8(buffer, &offset, 0x00);
    append_u8(buffer, &offset, 0x51);

    append_u16(buffer, &offset, 0x0303);
    for (i = 0; i < 32; i++) {
        append_u8(buffer, &offset, 0x00);
    }

    append_u8(buffer, &offset, 0x00);
    append_u16(buffer, &offset, 0x0002);
    append_u16(buffer, &offset, 0x1301);
    append_u8(buffer, &offset, 0x01);
    append_u8(buffer, &offset, 0x00);
    append_u16(buffer, &offset, 0x0026);

    append_u16(buffer, &offset, 0x0000);
    append_u16(buffer, &offset, 0x0010);
    append_u16(buffer, &offset, 0x000e);
    append_u8(buffer, &offset, 0x00);
    append_u16(buffer, &offset, 0x000b);
    memcpy(buffer + offset, "example.com", 11);
    offset += 11;

    append_u16(buffer, &offset, 0x0010);
    append_u16(buffer, &offset, 0x000e);
    append_u16(buffer, &offset, 0x000c);
    append_u8(buffer, &offset, 0x02);
    memcpy(buffer + offset, "h2", 2);
    offset += 2;
    append_u8(buffer, &offset, 0x08);
    memcpy(buffer + offset, "http/1.1", 8);
    offset += 8;

    assert(offset <= buffer_size);
    return offset;
}

static void test_app_tls_decode_client_hello(void) {
    uint8_t payload[128];
    AppInfo info;
    size_t length = build_client_hello(payload, sizeof(payload));

    assert(app_tls_decode_client_hello(payload, length, &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_TLS);
    assert(info.tls_record_version == 0x0303);
    assert(info.tls_handshake_type == 0x01);
    assert(info.tls_client_version == 0x0303);
    assert(strcmp(info.tls_sni, "example.com") == 0);
    assert(strcmp(info.tls_alpn, "h2,http/1.1") == 0);
}

static void test_app_tls_decode_need_more(void) {
    const uint8_t payload[] = {0x16, 0x03, 0x03};
    AppInfo info;

    assert(app_tls_decode_client_hello(payload, sizeof(payload), &info) == APP_DECODE_NEED_MORE);
}

static void test_app_tls_decode_no_match_for_non_tls(void) {
    const uint8_t payload[] = {0x17, 0x03, 0x03, 0x00, 0x01, 0x00};
    AppInfo info;

    assert(app_tls_decode_client_hello(payload, sizeof(payload), &info) == APP_DECODE_NO_MATCH);
}

static void test_app_tls_decode_malformed_client_hello(void) {
    const uint8_t payload[] = {
        0x16, 0x03, 0x03, 0x00, 0x04,
        0x01, 0x00, 0x00, 0x00
    };
    AppInfo info;

    assert(app_tls_decode_client_hello(payload, sizeof(payload), &info) == APP_DECODE_MALFORMED);
}

int main(void) {
    test_app_tls_decode_client_hello();
    test_app_tls_decode_need_more();
    test_app_tls_decode_no_match_for_non_tls();
    test_app_tls_decode_malformed_client_hello();

    printf("All app TLS tests passed.\n");

    return 0;
}
