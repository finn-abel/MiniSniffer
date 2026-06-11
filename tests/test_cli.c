#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "cli.h"
#include "config.h"

static void test_cli_parse_args_accepts_no_args(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer"};

    config_init_defaults(&config);

    assert(cli_parse_args(1, argv, &config) == 0);
}

static void test_cli_parse_args_accepts_help(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--help"};

    config_init_defaults(&config);

    assert(cli_parse_args(2, argv, &config) == 0);
}

static void test_cli_parse_args_sets_interface(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--interface", "en0"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(strcmp(config.interface_name, "en0") == 0);
}

static void test_cli_parse_args_sets_count(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--count", "10"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.max_packets == 10);
}

static void test_cli_parse_args_sets_protocol(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--protocol", "tcp"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.filter_protocol_enabled == 1);
    assert(config.filter_protocol == PROTO_TCP);
}

static void test_cli_parse_args_sets_port(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--port", "443"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.filter_port_enabled == 1);
    assert(config.filter_port == 443);
}

static void test_cli_parse_args_sets_host(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--host", "8.8.8.8"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.filter_host_enabled == 1);
    assert(strcmp(config.filter_host, "8.8.8.8") == 0);
}

static void test_cli_parse_args_sets_log(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--log", "packets.csv"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.logging_enabled == 1);
    assert(strcmp(config.log_path, "packets.csv") == 0);
}

static void test_cli_parse_args_sets_stats(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--stats"};

    config_init_defaults(&config);

    assert(cli_parse_args(2, argv, &config) == 0);
    assert(config.stats_mode == 1);
}

static void test_cli_parse_args_sets_payload_display(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--payload", "--payload-bytes", "32"};

    config_init_defaults(&config);

    assert(cli_parse_args(4, argv, &config) == 0);
    assert(config.payload_display_enabled == 1);
    assert(config.payload_preview_bytes == 32);
}

static void test_cli_parse_args_sets_payload_text_filter(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--payload-contains", "GET "};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.filter_payload_text_enabled == 1);
    assert(config.filter_payload_text_length == 4);
    assert(memcmp(config.filter_payload_text, "GET ", 4) == 0);
}

static void test_cli_parse_args_sets_payload_hex_filter(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--payload-hex", "47 45 54"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.filter_payload_hex_enabled == 1);
    assert(config.filter_payload_hex_length == 3);
    assert(config.filter_payload_hex[0] == 0x47);
    assert(config.filter_payload_hex[1] == 0x45);
    assert(config.filter_payload_hex[2] == 0x54);
}

static void test_cli_parse_args_sets_app_decode_options(void) {
    AppConfig config;
    char *argv[] = {
        "MiniSniffer",
        "--decode-app",
        "--reassemble",
        "--max-flows",
        "1024",
        "--stream-buffer-bytes",
        "32768",
        "--flow-timeout",
        "30"
    };

    config_init_defaults(&config);

    assert(cli_parse_args(9, argv, &config) == 0);
    assert(config.decode_app == true);
    assert(config.reassemble == true);
    assert(config.max_flows == 1024);
    assert(config.stream_buffer_bytes == 32768);
    assert(config.flow_timeout_seconds == 30);
}

static void test_cli_parse_args_accepts_supported_app_examples(void) {
    AppConfig config;
    char *decode_app[] = {"MiniSniffer", "--decode-app"};
    char *app_dns[] = {"MiniSniffer", "--decode-app", "--app", "dns"};
    char *http_host[] = {
        "MiniSniffer", "--decode-app", "--app", "http", "--http-host", "example.com"
    };
    char *tls_sni[] = {
        "MiniSniffer", "--decode-app", "--app", "tls", "--tls-sni", "example.com"
    };
    char *reassembled_tls_sni[] = {
        "MiniSniffer", "--decode-app", "--reassemble", "--tls-sni", "example.com"
    };
    char *stream_buffer[] = {
        "MiniSniffer", "--decode-app", "--reassemble", "--stream-buffer-bytes", "65536"
    };

    config_init_defaults(&config);
    assert(cli_parse_args(2, decode_app, &config) == 0);
    assert(config.decode_app);

    config_init_defaults(&config);
    assert(cli_parse_args(4, app_dns, &config) == 0);
    assert(config.filter_app_protocol == APP_PROTO_DNS);

    config_init_defaults(&config);
    assert(cli_parse_args(6, http_host, &config) == 0);
    assert(config.filter_app_protocol == APP_PROTO_HTTP);
    assert(strcmp(config.filter_http_host, "example.com") == 0);

    config_init_defaults(&config);
    assert(cli_parse_args(6, tls_sni, &config) == 0);
    assert(config.filter_app_protocol == APP_PROTO_TLS);
    assert(strcmp(config.filter_tls_sni, "example.com") == 0);

    config_init_defaults(&config);
    assert(cli_parse_args(5, reassembled_tls_sni, &config) == 0);
    assert(config.reassemble);
    assert(strcmp(config.filter_tls_sni, "example.com") == 0);

    config_init_defaults(&config);
    assert(cli_parse_args(5, stream_buffer, &config) == 0);
    assert(config.reassemble);
    assert(config.stream_buffer_bytes == 65536);
}

static void test_cli_parse_args_sets_app_filters(void) {
    AppConfig config;
    char *argv[] = {
        "MiniSniffer",
        "--decode-app",
        "--app",
        "http",
        "--http-host",
        "example.com",
        "--http-method",
        "GET",
        "--dns-query",
        "example.com",
        "--dns-type",
        "A",
        "--tls-sni",
        "example.com",
        "--tls-alpn",
        "h2"
    };

    config_init_defaults(&config);

    assert(cli_parse_args(16, argv, &config) == 0);
    assert(config.filter_app_enabled == true);
    assert(config.filter_app_protocol == APP_PROTO_HTTP);
    assert(config.filter_http_host_enabled == true);
    assert(strcmp(config.filter_http_host, "example.com") == 0);
    assert(config.filter_http_method_enabled == true);
    assert(strcmp(config.filter_http_method, "GET") == 0);
    assert(config.filter_dns_query_enabled == true);
    assert(strcmp(config.filter_dns_query, "example.com") == 0);
    assert(config.filter_dns_type_enabled == true);
    assert(config.filter_dns_type == 1);
    assert(config.filter_tls_sni_enabled == true);
    assert(strcmp(config.filter_tls_sni, "example.com") == 0);
    assert(config.filter_tls_alpn_enabled == true);
    assert(strcmp(config.filter_tls_alpn, "h2") == 0);
}

static void test_cli_parse_args_accepts_combined_filters(void) {
    AppConfig config;
    char *argv[] = {
        "MiniSniffer", "--protocol", "tcp", "--port", "443", "--count", "10"
    };

    config_init_defaults(&config);

    assert(cli_parse_args(7, argv, &config) == 0);
    assert(config.filter_protocol_enabled == 1);
    assert(config.filter_protocol == PROTO_TCP);
    assert(config.filter_port_enabled == 1);
    assert(config.filter_port == 443);
    assert(config.max_packets == 10);
}

static void test_cli_parse_args_rejects_unknown_flag(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--badflag"};

    config_init_defaults(&config);

    assert(cli_parse_args(2, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_missing_value(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--interface"};

    config_init_defaults(&config);

    assert(cli_parse_args(2, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_fake_protocol(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--protocol", "fake"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_invalid_port(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--port", "99999"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_zero_count(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--count", "0"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_long_host(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--host", "255.255.255.2555"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_invalid_host(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--host", "999.1.1.1"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_invalid_payload_options(void) {
    AppConfig config;
    char *payload_bytes[] = {"MiniSniffer", "--payload-bytes", "999"};
    char *payload_hex[] = {"MiniSniffer", "--payload-hex", "abc"};

    config_init_defaults(&config);
    assert(cli_parse_args(3, payload_bytes, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(3, payload_hex, &config) != 0);
}

static void test_cli_parse_args_rejects_invalid_app_decode_options(void) {
    AppConfig config;
    char *reassemble_without_decode[] = {"MiniSniffer", "--reassemble"};
    char *max_flows_zero[] = {"MiniSniffer", "--decode-app", "--reassemble", "--max-flows", "0"};
    char *stream_buffer_negative[] = {
        "MiniSniffer", "--decode-app", "--reassemble", "--stream-buffer-bytes", "-1"
    };
    char *flow_timeout_bad[] = {
        "MiniSniffer", "--decode-app", "--reassemble", "--flow-timeout", "abc"
    };
    char *max_flows_without_reassemble[] = {"MiniSniffer", "--decode-app", "--max-flows", "10"};
    char *stream_buffer_without_reassemble[] = {
        "MiniSniffer", "--decode-app", "--stream-buffer-bytes", "1024"
    };
    char *flow_timeout_without_reassemble[] = {
        "MiniSniffer", "--decode-app", "--flow-timeout", "10"
    };

    config_init_defaults(&config);
    assert(cli_parse_args(2, reassemble_without_decode, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(5, max_flows_zero, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(5, stream_buffer_negative, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(5, flow_timeout_bad, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(4, max_flows_without_reassemble, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(4, stream_buffer_without_reassemble, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(4, flow_timeout_without_reassemble, &config) != 0);
}

static void test_cli_parse_args_rejects_app_filters_without_decode_app(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--app", "dns"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_invalid_app_filters(void) {
    AppConfig config;
    char *bad_app[] = {"MiniSniffer", "--decode-app", "--app", "smtp"};
    char *bad_dns_type[] = {"MiniSniffer", "--decode-app", "--dns-type", "NOPE"};

    config_init_defaults(&config);
    assert(cli_parse_args(4, bad_app, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(4, bad_dns_type, &config) != 0);
}

static void test_cli_print_usage_accepts_null_program_name(void) {
    cli_print_usage(NULL);
}

int main(void) {
    test_cli_parse_args_accepts_no_args();
    test_cli_parse_args_accepts_help();
    test_cli_parse_args_sets_interface();
    test_cli_parse_args_sets_count();
    test_cli_parse_args_sets_protocol();
    test_cli_parse_args_sets_port();
    test_cli_parse_args_sets_host();
    test_cli_parse_args_sets_log();
    test_cli_parse_args_sets_stats();
    test_cli_parse_args_sets_payload_display();
    test_cli_parse_args_sets_payload_text_filter();
    test_cli_parse_args_sets_payload_hex_filter();
    test_cli_parse_args_sets_app_decode_options();
    test_cli_parse_args_accepts_supported_app_examples();
    test_cli_parse_args_sets_app_filters();
    test_cli_parse_args_accepts_combined_filters();
    test_cli_parse_args_rejects_unknown_flag();
    test_cli_parse_args_rejects_missing_value();
    test_cli_parse_args_rejects_fake_protocol();
    test_cli_parse_args_rejects_invalid_port();
    test_cli_parse_args_rejects_zero_count();
    test_cli_parse_args_rejects_long_host();
    test_cli_parse_args_rejects_invalid_host();
    test_cli_parse_args_rejects_invalid_payload_options();
    test_cli_parse_args_rejects_invalid_app_decode_options();
    test_cli_parse_args_rejects_app_filters_without_decode_app();
    test_cli_parse_args_rejects_invalid_app_filters();
    test_cli_print_usage_accepts_null_program_name();

    printf("All cli tests passed.\n");

    return 0;
}
