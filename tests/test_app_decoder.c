#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_decoder.h"
#include "fixtures/app_fixtures.h"

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
    AppInfo info;

    assert(app_decode_buffer(APP_PROTO_UNKNOWN,
                             HTTP_GET_WITH_HOST,
                             sizeof(HTTP_GET_WITH_HOST) - 1,
                             &info) ==
           APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_HTTP);
    assert(strcmp(info.http_method, "GET") == 0);
}

static void test_app_decode_buffer_reports_tls_need_more(void) {
    AppInfo info;

    assert(app_decode_buffer(APP_PROTO_UNKNOWN, TLS_TRUNCATED, sizeof(TLS_TRUNCATED), &info) ==
           APP_DECODE_NEED_MORE);
}

static void test_app_decode_buffer_detects_tls(void) {
    AppInfo info;

    assert(app_decode_buffer(APP_PROTO_UNKNOWN,
                             TLS_CLIENT_HELLO_SNI_ALPN,
                             sizeof(TLS_CLIENT_HELLO_SNI_ALPN),
                             &info) ==
           APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_TLS);
    assert(info.tls_handshake_type == 0x01);
}

static void test_app_decode_buffer_reports_preferred_empty_need_more(void) {
    AppInfo info;

    assert(app_decode_buffer(APP_PROTO_TLS, (const uint8_t *)"", 0, &info) ==
           APP_DECODE_NEED_MORE);
}

static void test_app_decode_packet_uses_ports_for_dns(void) {
    PacketInfo packet = make_payload_packet(PROTO_UDP, 54000, 53, DNS_A_QUERY, sizeof(DNS_A_QUERY));
    AppInfo info;

    assert(app_decode_packet(&packet, &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_DNS);
    assert(strcmp(info.dns_query_name, "www.example.com") == 0);
}

static void test_app_decode_packet_can_write_packet_app(void) {
    PacketInfo packet = make_payload_packet(PROTO_TCP,
                                            50000,
                                            80,
                                            HTTP_GET_WITH_HOST,
                                            sizeof(HTTP_GET_WITH_HOST) - 1);

    assert(app_decode_packet(&packet, &packet.app) == APP_DECODE_OK);
    assert(packet.app.protocol == APP_PROTO_HTTP);
    assert(strcmp(packet.app.http_host, "example.com") == 0);
}

static void test_app_decode_packet_uses_tcp_dns_frame(void) {
    uint8_t frame[sizeof(DNS_A_QUERY) + 2];
    PacketInfo packet;
    AppInfo info;

    frame[0] = 0x00;
    frame[1] = (uint8_t)sizeof(DNS_A_QUERY);
    memcpy(frame + 2, DNS_A_QUERY, sizeof(DNS_A_QUERY));
    packet = make_payload_packet(PROTO_TCP, 50000, 53, frame, sizeof(frame));

    assert(app_decode_packet(&packet, &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_DNS);
    assert(strcmp(info.dns_query_name, "www.example.com") == 0);
}

static void test_app_decode_packet_reports_preferred_malformed(void) {
    PacketInfo packet = make_payload_packet(PROTO_TCP,
                                            50000,
                                            80,
                                            HTTP_NO_MATCH,
                                            sizeof(HTTP_NO_MATCH) - 1);
    AppInfo info;

    assert(app_decode_packet(&packet, &info) == APP_DECODE_MALFORMED);
    assert(info.protocol == APP_PROTO_UNKNOWN);
}

static void test_app_decode_packet_rejects_empty_payload(void) {
    AppInfo info;

    assert(app_decode_packet(NULL, &info) == APP_DECODE_NO_MATCH);
}

static void test_app_decode_buffer_reports_malformed(void) {
    AppInfo info;

    assert(app_decode_buffer(APP_PROTO_HTTP,
                             HTTP_MALFORMED,
                             sizeof(HTTP_MALFORMED) - 1,
                             &info) == APP_DECODE_MALFORMED);
}

int main(void) {
    test_app_decode_buffer_detects_http();
    test_app_decode_buffer_reports_tls_need_more();
    test_app_decode_buffer_detects_tls();
    test_app_decode_buffer_reports_preferred_empty_need_more();
    test_app_decode_packet_uses_ports_for_dns();
    test_app_decode_packet_can_write_packet_app();
    test_app_decode_packet_uses_tcp_dns_frame();
    test_app_decode_packet_reports_preferred_malformed();
    test_app_decode_packet_rejects_empty_payload();
    test_app_decode_buffer_reports_malformed();

    printf("All app decoder tests passed.\n");

    return 0;
}
