#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "cli.h"
#include "config.h"

static void test_cli_parse_args_accepts_no_args(void) {
    AppConfig config;
    char *argv[] = {"PacketScope"};

    config_init_defaults(&config);

    assert(cli_parse_args(1, argv, &config) == 0);
}

static void test_cli_parse_args_accepts_help(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--help"};

    config_init_defaults(&config);

    assert(cli_parse_args(2, argv, &config) == 0);
}

static void test_cli_parse_args_sets_interface(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--interface", "en0"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(strcmp(config.interface_name, "en0") == 0);
}

static void test_cli_parse_args_sets_count(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--count", "10"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.max_packets == 10);
}

static void test_cli_parse_args_sets_protocol(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--protocol", "tcp"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.filter_protocol_enabled == 1);
    assert(config.filter_protocol == PROTO_TCP);
}

static void test_cli_parse_args_sets_port(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--port", "443"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.filter_port_enabled == 1);
    assert(config.filter_port == 443);
}

static void test_cli_parse_args_sets_host(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--host", "8.8.8.8"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.filter_host_enabled == 1);
    assert(strcmp(config.filter_host, "8.8.8.8") == 0);
}

static void test_cli_parse_args_sets_log(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--log", "packets.csv"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.logging_enabled == 1);
    assert(strcmp(config.log_path, "packets.csv") == 0);
}

static void test_cli_parse_args_sets_stats(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--stats"};

    config_init_defaults(&config);

    assert(cli_parse_args(2, argv, &config) == 0);
    assert(config.stats_mode == 1);
}

static void test_cli_parse_args_sets_payload_display(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--payload", "--payload-bytes", "32"};

    config_init_defaults(&config);

    assert(cli_parse_args(4, argv, &config) == 0);
    assert(config.payload_display_enabled == 1);
    assert(config.payload_preview_bytes == 32);
}

static void test_cli_parse_args_sets_payload_text_filter(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--payload-contains", "GET "};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.filter_payload_text_enabled == 1);
    assert(config.filter_payload_text_length == 4);
    assert(memcmp(config.filter_payload_text, "GET ", 4) == 0);
}

static void test_cli_parse_args_sets_payload_hex_filter(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--payload-hex", "47 45 54"};

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
        "PacketScope",
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

static void test_cli_parse_args_accepts_combined_filters(void) {
    AppConfig config;
    char *argv[] = {
        "PacketScope", "--protocol", "tcp", "--port", "443", "--count", "10"
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
    char *argv[] = {"PacketScope", "--badflag"};

    config_init_defaults(&config);

    assert(cli_parse_args(2, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_missing_value(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--interface"};

    config_init_defaults(&config);

    assert(cli_parse_args(2, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_fake_protocol(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--protocol", "fake"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_invalid_port(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--port", "99999"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_zero_count(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--count", "0"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_long_host(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--host", "255.255.255.2555"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_invalid_host(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--host", "999.1.1.1"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_invalid_payload_options(void) {
    AppConfig config;
    char *payload_bytes[] = {"PacketScope", "--payload-bytes", "999"};
    char *payload_hex[] = {"PacketScope", "--payload-hex", "abc"};

    config_init_defaults(&config);
    assert(cli_parse_args(3, payload_bytes, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(3, payload_hex, &config) != 0);
}

static void test_cli_parse_args_rejects_invalid_app_decode_options(void) {
    AppConfig config;
    char *reassemble_without_decode[] = {"PacketScope", "--reassemble"};
    char *max_flows_zero[] = {"PacketScope", "--max-flows", "0"};
    char *stream_buffer_negative[] = {"PacketScope", "--stream-buffer-bytes", "-1"};
    char *flow_timeout_bad[] = {"PacketScope", "--flow-timeout", "abc"};

    config_init_defaults(&config);
    assert(cli_parse_args(2, reassemble_without_decode, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(3, max_flows_zero, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(3, stream_buffer_negative, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(3, flow_timeout_bad, &config) != 0);
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
    test_cli_print_usage_accepts_null_program_name();

    printf("All cli tests passed.\n");

    return 0;
}
