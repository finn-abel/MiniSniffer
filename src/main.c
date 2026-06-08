#include <stdio.h>
#include <string.h>

#include "config.h"

const char *protocol_to_string(Protocol protocol) {
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

void config_init_defaults(AppConfig *config) {
    if (config == NULL) {
        return;
    }

    memset(config, 0, sizeof(*config));
    snprintf(config->interface_name, sizeof(config->interface_name), "default");
    config->max_packets = 0;
    config->stats_mode = 0;
    config->filter_protocol_enabled = 0;
    config->filter_protocol = PROTO_OTHER;
    config->filter_port_enabled = 0;
    config->filter_port = 0;
    config->filter_host_enabled = 0;
    config->logging_enabled = 0;
}

int main(void) {
    AppConfig config;

    config_init_defaults(&config);

    printf("PacketScope starting...\n");
    printf("Interface: %s\n", config.interface_name);
    printf("Max packets: %s\n",
           config.max_packets == 0 ? "unlimited" : "configured");

    return 0;
}
