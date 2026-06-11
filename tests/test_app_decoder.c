#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_decoder.h"

static PacketInfo make_payload_packet(
    Protocol protocol,
    uint16_t src_port,
    uint16_t dst_port,
    const uint8_t *payload,
    size_t payload_length
) {
    PacketInfo packet;

    memset(&packet, 0, sizeof(packet));
    packet.protocol = protocol;
    packet.has_ports = 1;
    packet.src_port = src_port;
    packet.dst_port = dst_port;
    packet.has_payload = payload_length > 0;
    packet.payload = payload;
    packet.payload_capture_length = payload_length;
    packet.payload_decode_length = payload_length;
    packet.payload_preview_length = payload_length > PACKETSCOPE_MAX_PAYLOAD_PREVIEW_BYTES
        ? PACKETSCOPE_MAX_PAYLOAD_PREVIEW_BYTES
        : payload_length;

    return packet;
}

static void test_app_decode_buffer_detects_http(void) {
    const uint8_t payload[] = "GET / HTTP/1.1\r\n";
    AppInfo info;

    assert(app_decode_buffer(APP_PROTO_UNKNOWN, payload, sizeof(payload) - 1, &info) ==
           APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_HTTP);
    assert(strcmp(info.summary, "HTTP/1.x") == 0);
}

static void test_app_decode_buffer_reports_tls_need_more(void) {
    const uint8_t payload[] = {0x16, 0x03, 0x03};
    AppInfo info;

    assert(app_decode_buffer(APP_PROTO_UNKNOWN, payload, sizeof(payload), &info) ==
           APP_DECODE_NEED_MORE);
}

static void test_app_decode_buffer_detects_tls(void) {
    const uint8_t payload[] = {
        0x16, 0x03, 0x03, 0x00, 0x04,
        0x01, 0x00, 0x00, 0x00
    };
    AppInfo info;

    assert(app_decode_buffer(APP_PROTO_UNKNOWN, payload, sizeof(payload), &info) ==
           APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_TLS);
}

static void test_app_decode_buffer_reports_preferred_empty_need_more(void) {
    AppInfo info;

    assert(app_decode_buffer(APP_PROTO_TLS, (const uint8_t *)"", 0, &info) ==
           APP_DECODE_NEED_MORE);
}

static void test_app_decode_packet_uses_ports_for_dns(void) {
    const uint8_t payload[] = {
        0x12, 0x34, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    PacketInfo packet = make_payload_packet(PROTO_UDP, 54000, 53, payload, sizeof(payload));
    AppInfo info;

    assert(app_decode_packet(&packet, &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_DNS);
}

static void test_app_decode_packet_reports_preferred_malformed(void) {
    const uint8_t payload[] = "not http";
    PacketInfo packet = make_payload_packet(PROTO_TCP, 50000, 80, payload, sizeof(payload) - 1);
    AppInfo info;

    assert(app_decode_packet(&packet, &info) == APP_DECODE_MALFORMED);
    assert(info.protocol == APP_PROTO_UNKNOWN);
}

static void test_app_decode_packet_rejects_empty_payload(void) {
    AppInfo info;

    assert(app_decode_packet(NULL, &info) == APP_DECODE_NO_MATCH);
}

int main(void) {
    test_app_decode_buffer_detects_http();
    test_app_decode_buffer_reports_tls_need_more();
    test_app_decode_buffer_detects_tls();
    test_app_decode_buffer_reports_preferred_empty_need_more();
    test_app_decode_packet_uses_ports_for_dns();
    test_app_decode_packet_reports_preferred_malformed();
    test_app_decode_packet_rejects_empty_payload();

    printf("All app decoder tests passed.\n");

    return 0;
}
