#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_decoder.h"
#include "fixtures/app_fixtures.h"

static PacketInfo make_payload_packet(Protocol protocol, uint16_t src_port, uint16_t dst_port,
                                      const uint8_t *payload, size_t payload_length) {
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
    packet.payload_preview_length = payload_length > MINISNIFFER_MAX_PAYLOAD_PREVIEW_BYTES
                                        ? MINISNIFFER_MAX_PAYLOAD_PREVIEW_BYTES
                                        : payload_length;

    return packet;
}

static void test_app_decode_buffer_detects_http(void) {
    AppInfo info;

    assert(app_decode_buffer(APP_PROTO_UNKNOWN, HTTP_GET_WITH_HOST, sizeof(HTTP_GET_WITH_HOST) - 1,
                             &info) == APP_DECODE_OK);
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

    assert(app_decode_buffer(APP_PROTO_UNKNOWN, TLS_CLIENT_HELLO_SNI_ALPN,
                             sizeof(TLS_CLIENT_HELLO_SNI_ALPN), &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_TLS);
    assert(info.tls_handshake_type == 0x01);
}

static void test_app_decode_buffer_reports_preferred_empty_need_more(void) {
    AppInfo info;

    assert(app_decode_buffer(APP_PROTO_TLS, (const uint8_t *)"", 0, &info) == APP_DECODE_NEED_MORE);
}

static void test_app_decode_packet_uses_ports_for_dns(void) {
    PacketInfo packet = make_payload_packet(PROTO_UDP, 54000, 53, DNS_A_QUERY, sizeof(DNS_A_QUERY));
    AppInfo info;

    assert(app_decode_packet(&packet, &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_DNS);
    assert(strcmp(info.dns_query_name, "www.example.com") == 0);
}

static void test_app_decode_packet_works_with_ipv6_tcp_and_udp(void) {
    PacketInfo http_packet = make_payload_packet(PROTO_TCP, 50000, 80, HTTP_GET_WITH_HOST,
                                                 sizeof(HTTP_GET_WITH_HOST) - 1);
    PacketInfo dns_packet =
        make_payload_packet(PROTO_UDP, 54000, 53, DNS_A_QUERY, sizeof(DNS_A_QUERY));
    AppInfo info;

    http_packet.ip_version = 6;
    snprintf(http_packet.src_ip, sizeof(http_packet.src_ip), "2001:db8::1");
    snprintf(http_packet.dst_ip, sizeof(http_packet.dst_ip), "2001:db8::2");
    assert(app_decode_packet(&http_packet, &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_HTTP);
    assert(strcmp(info.http_host, "example.com") == 0);

    dns_packet.ip_version = 6;
    snprintf(dns_packet.src_ip, sizeof(dns_packet.src_ip), "2001:db8::1");
    snprintf(dns_packet.dst_ip, sizeof(dns_packet.dst_ip), "2001:db8::2");
    assert(app_decode_packet(&dns_packet, &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_DNS);
    assert(strcmp(info.dns_query_name, "www.example.com") == 0);
}

static void test_app_decode_packet_can_write_packet_app(void) {
    PacketInfo packet = make_payload_packet(PROTO_TCP, 50000, 80, HTTP_GET_WITH_HOST,
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
    PacketInfo packet =
        make_payload_packet(PROTO_TCP, 50000, 80, HTTP_NO_MATCH, sizeof(HTTP_NO_MATCH) - 1);
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

    assert(app_decode_buffer(APP_PROTO_HTTP, HTTP_MALFORMED, sizeof(HTTP_MALFORMED) - 1, &info) ==
           APP_DECODE_MALFORMED);
}

static void test_app_decode_buffer_handles_all_preferences(void) {
    AppInfo info;

    memset(&info, 0xff, sizeof(info));
    assert(app_decode_buffer(APP_PROTO_UNKNOWN, NULL, 1, &info) == APP_DECODE_NO_MATCH);
    assert(info.protocol == APP_PROTO_UNKNOWN);
    assert(app_decode_buffer(APP_PROTO_UNKNOWN, (const uint8_t *)"", 0, NULL) ==
           APP_DECODE_NO_MATCH);

    assert(app_decode_buffer(APP_PROTO_TLS, TLS_CLIENT_HELLO_SNI, sizeof(TLS_CLIENT_HELLO_SNI),
                             &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_TLS);

    assert(app_decode_buffer(APP_PROTO_DNS, DNS_A_QUERY, sizeof(DNS_A_QUERY), &info) ==
           APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_DNS);

    assert(app_decode_buffer(APP_PROTO_DNS, HTTP_NO_MATCH, sizeof(HTTP_NO_MATCH) - 1, &info) ==
           APP_DECODE_MALFORMED);
    assert(info.protocol == APP_PROTO_UNKNOWN);
}

static void test_app_decode_buffer_sniffs_dns_and_rejects_random_data(void) {
    static const uint8_t random_data[] = {0xff, 0x00, 0x01, 0x02};
    AppInfo info;

    assert(app_decode_buffer(APP_PROTO_UNKNOWN, DNS_A_QUERY, sizeof(DNS_A_QUERY), &info) ==
           APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_DNS);
    assert(app_decode_buffer(APP_PROTO_UNKNOWN, random_data, sizeof(random_data), &info) ==
           APP_DECODE_NO_MATCH);
    assert(info.protocol == APP_PROTO_UNKNOWN);
}

static void test_app_decode_packet_sniffs_signatures_without_ports(void) {
    PacketInfo packet =
        make_payload_packet(PROTO_OTHER, 0, 0, HTTP_GET_WITH_HOST, sizeof(HTTP_GET_WITH_HOST) - 1);
    AppInfo info;

    packet.has_ports = 0;
    assert(app_decode_packet(&packet, &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_HTTP);

    packet.payload = TLS_CLIENT_HELLO_SNI;
    packet.payload_capture_length = sizeof(TLS_CLIENT_HELLO_SNI);
    packet.payload_decode_length = sizeof(TLS_CLIENT_HELLO_SNI);
    assert(app_decode_packet(&packet, &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_TLS);

    packet.payload = DNS_A_QUERY;
    packet.payload_capture_length = sizeof(DNS_A_QUERY);
    packet.payload_decode_length = sizeof(DNS_A_QUERY);
    assert(app_decode_packet(&packet, &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_DNS);

    packet.payload = HTTP_NO_MATCH;
    packet.payload_capture_length = sizeof(HTTP_NO_MATCH) - 1;
    packet.payload_decode_length = sizeof(HTTP_NO_MATCH) - 1;
    assert(app_decode_packet(&packet, &info) == APP_DECODE_NO_MATCH);
    assert(info.protocol == APP_PROTO_UNKNOWN);
}

static void test_app_decode_packet_uses_tls_ports(void) {
    PacketInfo packet = make_payload_packet(PROTO_TCP, 8443, 50000, TLS_CLIENT_HELLO_SNI,
                                            sizeof(TLS_CLIENT_HELLO_SNI));
    AppInfo info;

    assert(app_decode_packet(&packet, &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_TLS);
}

static void test_app_decode_packet_rejects_invalid_payload_views(void) {
    PacketInfo packet;
    AppInfo info;

    memset(&packet, 0, sizeof(packet));
    packet.has_payload = 1;
    packet.payload_decode_length = 1;
    assert(app_decode_packet(&packet, &info) == APP_DECODE_NO_MATCH);

    packet.payload = HTTP_NO_MATCH;
    packet.payload_decode_length = 0;
    assert(app_decode_packet(&packet, &info) == APP_DECODE_NO_MATCH);

    packet.has_payload = 0;
    packet.payload_decode_length = sizeof(HTTP_NO_MATCH) - 1;
    assert(app_decode_packet(&packet, NULL) == APP_DECODE_NO_MATCH);
}

static void test_app_decode_stream_uses_hints_and_fallback(void) {
    uint8_t dns_frame[sizeof(DNS_A_QUERY) + 2];
    PacketInfo packet;
    AppInfo info;

    assert(app_decode_stream(NULL, HTTP_GET_WITH_HOST, sizeof(HTTP_GET_WITH_HOST) - 1, &info) ==
           APP_DECODE_NO_MATCH);
    memset(&packet, 0, sizeof(packet));
    assert(app_decode_stream(&packet, NULL, 1, &info) == APP_DECODE_NO_MATCH);
    assert(app_decode_stream(&packet, HTTP_GET_WITH_HOST, 0, &info) == APP_DECODE_NO_MATCH);

    packet = make_payload_packet(PROTO_TCP, 50000, 8080, NULL, 0);
    assert(app_decode_stream(&packet, HTTP_GET_WITH_HOST, sizeof(HTTP_GET_WITH_HOST) - 1, &info) ==
           APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_HTTP);

    packet.src_port = 443;
    packet.dst_port = 50000;
    assert(app_decode_stream(&packet, TLS_CLIENT_HELLO_SNI, sizeof(TLS_CLIENT_HELLO_SNI), &info) ==
           APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_TLS);

    dns_frame[0] = 0;
    dns_frame[1] = (uint8_t)sizeof(DNS_A_QUERY);
    memcpy(dns_frame + 2, DNS_A_QUERY, sizeof(DNS_A_QUERY));
    packet.src_port = 50000;
    packet.dst_port = 53;
    assert(app_decode_stream(&packet, dns_frame, sizeof(dns_frame), &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_DNS);

    packet.protocol = PROTO_OTHER;
    packet.has_ports = 0;
    assert(app_decode_stream(&packet, HTTP_GET_WITH_HOST, sizeof(HTTP_GET_WITH_HOST) - 1, &info) ==
           APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_HTTP);
}

int main(void) {
    test_app_decode_buffer_detects_http();
    test_app_decode_buffer_reports_tls_need_more();
    test_app_decode_buffer_detects_tls();
    test_app_decode_buffer_reports_preferred_empty_need_more();
    test_app_decode_packet_uses_ports_for_dns();
    test_app_decode_packet_works_with_ipv6_tcp_and_udp();
    test_app_decode_packet_can_write_packet_app();
    test_app_decode_packet_uses_tcp_dns_frame();
    test_app_decode_packet_reports_preferred_malformed();
    test_app_decode_packet_rejects_empty_payload();
    test_app_decode_buffer_reports_malformed();
    test_app_decode_buffer_handles_all_preferences();
    test_app_decode_buffer_sniffs_dns_and_rejects_random_data();
    test_app_decode_packet_sniffs_signatures_without_ports();
    test_app_decode_packet_uses_tls_ports();
    test_app_decode_packet_rejects_invalid_payload_views();
    test_app_decode_stream_uses_hints_and_fallback();

    printf("All app decoder tests passed.\n");

    return 0;
}
