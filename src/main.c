#include <stdio.h>
#include <string.h>

#include "cli.h"
#include "config.h"

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

    /* Start from safe defaults before applying CLI options. */
    config_init_defaults(&config);
    if (cli_parse_args(argc, argv, &config) != 0) {
        return 1;
    }
    if (args_requested_help(argc, argv)) {
        return 0;
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
    if (config.logging_enabled != 0) {
        printf("Log file: %s\n", config.log_path);
    }

    return 0;
}
