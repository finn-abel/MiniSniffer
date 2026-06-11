#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_http.h"
#include "app_tls.h"
#include "filters.h"
#include "fixtures/app_fixtures.h"

static PacketInfo make_packet(void) {
    PacketInfo packet;

    memset(&packet, 0, sizeof(packet));
    packet.protocol = PROTO_TCP;
    packet.has_ports = 1;
    packet.src_port = 50000;
    packet.dst_port = 80;
    snprintf(packet.src_ip, sizeof(packet.src_ip), "192.168.1.25");
    snprintf(packet.dst_ip, sizeof(packet.dst_ip), "93.184.216.34");

    return packet;
}

static AppInfo make_http_app(void) {
    AppInfo app;

    assert(app_http_decode(HTTP_GET_WITH_HOST,
                           sizeof(HTTP_GET_WITH_HOST) - 1,
                           &app) == APP_DECODE_OK);

    return app;
}

static AppInfo make_tls_app(void) {
    AppInfo app;

    assert(app_tls_decode_client_hello(TLS_CLIENT_HELLO_SNI_ALPN,
                                       sizeof(TLS_CLIENT_HELLO_SNI_ALPN),
                                       &app) == APP_DECODE_OK);

    return app;
}

static void test_filters_match_packet_app(void) {
    AppConfig config;
    PacketInfo packet = make_packet();
    AppInfo app = make_http_app();
    FilterContext context;

    config_init_defaults(&config);
    config.filter_app_enabled = true;
    config.filter_app_protocol = APP_PROTO_HTTP;
    config.filter_http_host_enabled = true;
    snprintf(config.filter_http_host, sizeof(config.filter_http_host), "example.com");

    context.packet = &packet;
    context.packet_app = &app;
    context.flow_app = NULL;
    context.flow_is_classified = false;

    assert(filters_match(&config, &context));

    snprintf(config.filter_http_host, sizeof(config.filter_http_host), "other.example");
    assert(!filters_match(&config, &context));
}

static void test_filters_match_flow_app(void) {
    AppConfig config;
    PacketInfo packet = make_packet();
    AppInfo flow_app = make_tls_app();
    FilterContext context;

    config_init_defaults(&config);
    config.reassemble = true;
    config.filter_tls_alpn_enabled = true;
    snprintf(config.filter_tls_alpn, sizeof(config.filter_tls_alpn), "h2");

    context.packet = &packet;
    context.packet_app = NULL;
    context.flow_app = &flow_app;
    context.flow_is_classified = true;

    assert(filters_match(&config, &context));
}

static void test_reassembly_mode_ignores_packet_app_for_app_filters(void) {
    AppConfig config;
    PacketInfo packet = make_packet();
    AppInfo packet_app = make_http_app();
    FilterContext context;

    config_init_defaults(&config);
    config.reassemble = true;
    config.filter_app_enabled = true;
    config.filter_app_protocol = APP_PROTO_HTTP;

    context.packet = &packet;
    context.packet_app = &packet_app;
    context.flow_app = NULL;
    context.flow_is_classified = false;

    assert(!filters_match(&config, &context));
}

static void test_reassembly_mode_matches_future_classified_flow_packets(void) {
    AppConfig config;
    PacketInfo packet = make_packet();
    AppInfo flow_app = make_tls_app();
    FilterContext context;

    config_init_defaults(&config);
    config.reassemble = true;
    config.filter_app_enabled = true;
    config.filter_app_protocol = APP_PROTO_TLS;
    config.filter_tls_alpn_enabled = true;
    snprintf(config.filter_tls_alpn, sizeof(config.filter_tls_alpn), "h2");

    context.packet = &packet;
    context.packet_app = NULL;
    context.flow_app = &flow_app;
    context.flow_is_classified = true;

    assert(filters_match(&config, &context));
}

static void test_reassembly_mode_classifying_packet_does_not_match_yet(void) {
    AppConfig config;
    PacketInfo packet = make_packet();
    AppInfo flow_app = make_tls_app();
    FilterContext context;

    config_init_defaults(&config);
    config.reassemble = true;
    config.filter_app_enabled = true;
    config.filter_app_protocol = APP_PROTO_TLS;

    context.packet = &packet;
    context.packet_app = NULL;
    context.flow_app = &flow_app;
    context.flow_is_classified = false;

    assert(!filters_match(&config, &context));
}

static void test_filters_fail_without_app_data(void) {
    AppConfig config;
    PacketInfo packet = make_packet();
    FilterContext context;

    config_init_defaults(&config);
    config.filter_app_enabled = true;
    config.filter_app_protocol = APP_PROTO_DNS;

    context.packet = &packet;
    context.packet_app = NULL;
    context.flow_app = NULL;
    context.flow_is_classified = false;

    assert(!filters_match(&config, &context));
}

int main(void) {
    test_filters_match_packet_app();
    test_filters_match_flow_app();
    test_reassembly_mode_ignores_packet_app_for_app_filters();
    test_reassembly_mode_matches_future_classified_flow_packets();
    test_reassembly_mode_classifying_packet_does_not_match_yet();
    test_filters_fail_without_app_data();

    printf("All filters tests passed.\n");

    return 0;
}
