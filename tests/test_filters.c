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

    assert(app_http_decode(HTTP_GET_WITH_HOST, sizeof(HTTP_GET_WITH_HOST) - 1, &app) ==
           APP_DECODE_OK);

    return app;
}

static AppInfo make_tls_app(void) {
    AppInfo app;

    assert(app_tls_decode_client_hello(TLS_CLIENT_HELLO_SNI_ALPN, sizeof(TLS_CLIENT_HELLO_SNI_ALPN),
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

static void test_domain_filters_are_case_insensitive(void) {
    AppConfig config;
    PacketInfo packet = make_packet();
    AppInfo app = make_http_app();
    FilterContext context;

    config_init_defaults(&config);
    config.filter_http_host_enabled = true;
    snprintf(config.filter_http_host, sizeof(config.filter_http_host), "EXAMPLE.COM.");

    context.packet = &packet;
    context.packet_app = &app;
    context.flow_app = NULL;
    context.flow_is_classified = false;

    assert(filters_match(&config, &context));
}

static void test_filters_reject_invalid_contexts(void) {
    AppConfig config;
    PacketInfo packet = make_packet();
    FilterContext context;

    config_init_defaults(&config);
    memset(&context, 0, sizeof(context));
    assert(!filters_match(NULL, &context));
    assert(!filters_match(&config, NULL));
    assert(!filters_match(&config, &context));
    context.packet = &packet;
    assert(filters_match(&config, &context));
}

static void test_transport_and_payload_filter_failures(void) {
    static const unsigned char payload[] = "ABC";
    AppConfig config;
    PacketInfo packet = make_packet();
    FilterContext context;

    memset(&context, 0, sizeof(context));
    context.packet = &packet;

    config_init_defaults(&config);
    config.filter_protocol_enabled = 1;
    config.filter_protocol = PROTO_UDP;
    assert(!filters_match(&config, &context));

    config_init_defaults(&config);
    config.filter_port_enabled = 1;
    config.filter_port = 53;
    packet.has_ports = 0;
    assert(!filters_match(&config, &context));
    packet.has_ports = 1;
    assert(!filters_match(&config, &context));

    config_init_defaults(&config);
    config.filter_host_enabled = 1;
    snprintf(config.filter_host, sizeof(config.filter_host), "10.0.0.1");
    assert(!filters_match(&config, &context));

    config_init_defaults(&config);
    config.filter_payload_text_enabled = 1;
    memcpy(config.filter_payload_text, "A", 1);
    config.filter_payload_text_length = 1;
    packet.has_payload = 0;
    assert(!filters_match(&config, &context));
    packet.has_payload = 1;
    packet.payload = NULL;
    packet.payload_decode_length = 3;
    assert(!filters_match(&config, &context));
    packet.payload = payload;
    config.filter_payload_text_length = 4;
    assert(!filters_match(&config, &context));
    config.filter_payload_text_length = 0;
    assert(!filters_match(&config, &context));
    memcpy(config.filter_payload_text, "Z", 1);
    config.filter_payload_text_length = 1;
    assert(!filters_match(&config, &context));

    config_init_defaults(&config);
    config.filter_payload_hex_enabled = 1;
    config.filter_payload_hex[0] = 0xff;
    config.filter_payload_hex_length = 1;
    packet.has_payload = 0;
    assert(!filters_match(&config, &context));
}

static void test_app_filter_mismatch_paths(void) {
    AppConfig config;
    PacketInfo packet = make_packet();
    AppInfo app = make_http_app();
    FilterContext context;

    memset(&context, 0, sizeof(context));
    context.packet = &packet;
    context.packet_app = &app;

    config_init_defaults(&config);
    config.filter_app_enabled = true;
    config.filter_app_protocol = APP_PROTO_DNS;
    assert(!filters_match(&config, &context));

    config_init_defaults(&config);
    config.filter_http_method_enabled = true;
    snprintf(config.filter_http_method, sizeof(config.filter_http_method), "POST");
    assert(!filters_match(&config, &context));

    config_init_defaults(&config);
    config.filter_dns_query_enabled = true;
    snprintf(config.filter_dns_query, sizeof(config.filter_dns_query), "example.com");
    assert(!filters_match(&config, &context));

    config_init_defaults(&config);
    config.filter_dns_type_enabled = true;
    config.filter_dns_type = 1;
    assert(!filters_match(&config, &context));

    config_init_defaults(&config);
    config.filter_tls_sni_enabled = true;
    snprintf(config.filter_tls_sni, sizeof(config.filter_tls_sni), "example.com");
    assert(!filters_match(&config, &context));

    config_init_defaults(&config);
    config.filter_tls_alpn_enabled = true;
    snprintf(config.filter_tls_alpn, sizeof(config.filter_tls_alpn), "smtp");
    app = make_tls_app();
    context.packet_app = &app;
    assert(!filters_match(&config, &context));
}

static void test_domain_filter_handles_left_dot_and_character_mismatch(void) {
    AppConfig config;
    PacketInfo packet = make_packet();
    AppInfo app = make_http_app();
    FilterContext context;

    memset(&context, 0, sizeof(context));
    context.packet = &packet;
    context.packet_app = &app;
    config_init_defaults(&config);
    config.filter_http_host_enabled = true;
    snprintf(app.http_host, sizeof(app.http_host), "Example.COM.");
    snprintf(config.filter_http_host, sizeof(config.filter_http_host), "example.com");
    assert(filters_match(&config, &context));

    snprintf(config.filter_http_host, sizeof(config.filter_http_host), "example.net");
    assert(!filters_match(&config, &context));
}

int main(void) {
    test_filters_match_packet_app();
    test_filters_match_flow_app();
    test_reassembly_mode_ignores_packet_app_for_app_filters();
    test_reassembly_mode_matches_future_classified_flow_packets();
    test_reassembly_mode_classifying_packet_does_not_match_yet();
    test_filters_fail_without_app_data();
    test_domain_filters_are_case_insensitive();
    test_filters_reject_invalid_contexts();
    test_transport_and_payload_filter_failures();
    test_app_filter_mismatch_paths();
    test_domain_filter_handles_left_dot_and_character_mismatch();

    printf("All filters tests passed.\n");

    return 0;
}
