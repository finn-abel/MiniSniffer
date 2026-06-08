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

static void test_config_init_defaults_rejects_null_input(void) {
    config_init_defaults(NULL);
}

int main(void) {
    test_config_defaults_capture_options();
    test_config_defaults_protocol_filter();
    test_config_defaults_port_filter();
    test_config_defaults_host_filter();
    test_config_defaults_logging();
    test_config_init_defaults_rejects_null_input();

    printf("All config tests passed.\n");

    return 0;
}
