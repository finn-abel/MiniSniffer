#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "config.h"

static void test_config_defaults_capture_options(void) {
    AppConfig config;

    config_init_defaults(&config);

    assert(strcmp(config.interface_name, "") == 0);
    assert(config.max_packets == 0);
    assert(config.stats_mode == 0);
    assert(config.version_requested == false);
    assert(config.list_interfaces == false);
    assert(config.quiet == false);
    assert(config.verbose == false);
    assert(config.color_enabled == true);
}

static void test_config_defaults_app_decode_options(void) {
    AppConfig config;

    config_init_defaults(&config);

    assert(config.decode_app == false);
    assert(config.reassemble == false);
    assert(config.payload_decode_bytes == MINISNIFFER_DEFAULT_PAYLOAD_DECODE_BYTES);
    assert(config.payload_preview_bytes == MINISNIFFER_DEFAULT_PAYLOAD_PREVIEW_BYTES);
    assert(config.max_flows == MINISNIFFER_DEFAULT_MAX_FLOWS);
    assert(config.stream_buffer_bytes == MINISNIFFER_DEFAULT_STREAM_BUFFER_BYTES);
    assert(config.flow_timeout_seconds == MINISNIFFER_DEFAULT_FLOW_TIMEOUT_SECONDS);
}

static void test_config_defaults_protocol_filter(void) {
    AppConfig config;

    config_init_defaults(&config);

    assert(config.filter_protocol_enabled == 0);
    assert(config.filter_protocol == PROTO_OTHER);
}

static void test_config_defaults_port_filter(void) {
    AppConfig config;

    config_init_defaults(&config);

    assert(config.filter_port_enabled == 0);
    assert(config.filter_port == 0);
}

static void test_config_defaults_host_filter(void) {
    AppConfig config;

    config_init_defaults(&config);

    assert(config.filter_host_enabled == 0);
    assert(strcmp(config.filter_host, "") == 0);
}

static void test_config_defaults_logging(void) {
    AppConfig config;

    config_init_defaults(&config);

    assert(config.logging_enabled == 0);
    assert(strcmp(config.log_path, "") == 0);
}

static void test_config_defaults_payload_options(void) {
    AppConfig config;

    config_init_defaults(&config);

    assert(config.payload_display_enabled == 0);
    assert(config.filter_payload_text_enabled == 0);
    assert(config.filter_payload_text_length == 0);
    assert(config.filter_payload_hex_enabled == 0);
    assert(config.filter_payload_hex_length == 0);
}

static void test_config_defaults_app_filters(void) {
    AppConfig config;

    config_init_defaults(&config);

    assert(config.filter_app_enabled == false);
    assert(config.filter_app_protocol == APP_PROTO_UNKNOWN);
    assert(config.filter_http_host_enabled == false);
    assert(strcmp(config.filter_http_host, "") == 0);
    assert(config.filter_http_method_enabled == false);
    assert(strcmp(config.filter_http_method, "") == 0);
    assert(config.filter_dns_query_enabled == false);
    assert(strcmp(config.filter_dns_query, "") == 0);
    assert(config.filter_dns_type_enabled == false);
    assert(config.filter_dns_type == 0);
    assert(config.filter_tls_sni_enabled == false);
    assert(strcmp(config.filter_tls_sni, "") == 0);
    assert(config.filter_tls_alpn_enabled == false);
    assert(strcmp(config.filter_tls_alpn, "") == 0);
}

static void test_config_init_defaults_rejects_null_input(void) {
    config_init_defaults(NULL);
}

int main(void) {
    test_config_defaults_capture_options();
    test_config_defaults_app_decode_options();
    test_config_defaults_protocol_filter();
    test_config_defaults_port_filter();
    test_config_defaults_host_filter();
    test_config_defaults_logging();
    test_config_defaults_payload_options();
    test_config_defaults_app_filters();
    test_config_init_defaults_rejects_null_input();

    printf("All config tests passed.\n");

    return 0;
}
