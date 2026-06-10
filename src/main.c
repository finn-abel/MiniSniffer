#include <stdio.h>
#include <string.h>

#include "capture.h"
#include "cli.h"
#include "config.h"
#include "logger.h"
#include "stats.h"

static int args_requested_help(int argc, char **argv) {
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            return 1;
        }
    }

    return 0;
}

int main(int argc, char **argv) {
    AppConfig config;
    PacketStats stats;
    int capture_result;

    /* Start from safe defaults before applying CLI options. */
    config_init_defaults(&config);
    if (cli_parse_args(argc, argv, &config) != 0) {
        return 1;
    }
    if (args_requested_help(argc, argv)) {
        return 0;
    }

    stats_init(&stats);

    logger_set_payload_logging(config.payload_display_enabled,
                               config.payload_preview_bytes);

    if (config.logging_enabled != 0 && logger_open(config.log_path) != 0) {
        return 1;
    }

    printf("PacketScope starting...\n");
    printf("Interface: %s\n",
           config.interface_name[0] == '\0' ? "default" : config.interface_name);
    if (config.max_packets == 0) {
        printf("Max packets: unlimited\n");
    } else {
        printf("Max packets: %d\n", config.max_packets);
    }
    printf("Stats mode: %s\n", config.stats_mode != 0 ? "enabled" : "disabled");

    if (config.filter_protocol_enabled != 0) {
        printf("Protocol filter: %s\n", protocol_to_string(config.filter_protocol));
    }
    if (config.filter_port_enabled != 0) {
        printf("Port filter: %u\n", (unsigned int)config.filter_port);
    }
    if (config.filter_host_enabled != 0) {
        printf("Host filter: %s\n", config.filter_host);
    }
    if (config.filter_payload_text_enabled != 0) {
        printf("Payload text filter: %zu bytes\n", config.filter_payload_text_length);
    }
    if (config.filter_payload_hex_enabled != 0) {
        printf("Payload hex filter: %zu bytes\n", config.filter_payload_hex_length);
    }
    if (config.payload_display_enabled != 0) {
        printf("Payload preview: %zu bytes\n", config.payload_preview_bytes);
    }
    if (config.logging_enabled != 0) {
        printf("Log file: %s\n", config.log_path);
    }

    capture_result = capture_start(&config, &stats);
    logger_close();

    if (config.stats_mode != 0) {
        stats_print(&stats);
    }

    return capture_result;
}
