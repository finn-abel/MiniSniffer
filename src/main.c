#include <stdio.h>
#include <string.h>

#include "cli.h"
#include "config.h"

const char *protocol_to_string(Protocol protocol) {
    /* Keep display strings centralized so logs and summaries stay consistent. */
    switch (protocol) {
        case PROTO_TCP:
            return "TCP";
        case PROTO_UDP:
            return "UDP";
        case PROTO_ICMP:
            return "ICMP";
        case PROTO_OTHER:
        default:
            return "OTHER";
    }
}

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
    printf("Max packets: %s\n",
           config.max_packets == 0 ? "unlimited" : "configured");

    return 0;
}
