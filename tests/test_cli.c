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

static void test_protocol_from_string_accepts_known_values(void) {
    Protocol protocol;

    assert(protocol_from_string("tcp", &protocol) == 0);
    assert(protocol == PROTO_TCP);
    assert(protocol_from_string("udp", &protocol) == 0);
    assert(protocol == PROTO_UDP);
    assert(protocol_from_string("icmp", &protocol) == 0);
    assert(protocol == PROTO_ICMP);
    assert(protocol_from_string("other", &protocol) == 0);
    assert(protocol == PROTO_OTHER);
}

static void test_protocol_from_string_rejects_unknown_values(void) {
    Protocol protocol = PROTO_OTHER;

    assert(protocol_from_string("fake", &protocol) != 0);
    assert(protocol_from_string(NULL, &protocol) != 0);
    assert(protocol_from_string("tcp", NULL) != 0);
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
    test_cli_parse_args_accepts_combined_filters();
    test_cli_parse_args_rejects_unknown_flag();
    test_cli_parse_args_rejects_missing_value();
    test_cli_parse_args_rejects_fake_protocol();
    test_cli_parse_args_rejects_invalid_port();
    test_cli_parse_args_rejects_zero_count();
    test_cli_parse_args_rejects_long_host();
    test_protocol_from_string_accepts_known_values();
    test_protocol_from_string_rejects_unknown_values();
    test_cli_print_usage_accepts_null_program_name();

    printf("All cli tests passed.\n");

    return 0;
}
