#include <stdio.h>

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

int main(void) {
    AppConfig config;

    /* Start from safe defaults until CLI parsing is implemented. */
    config_init_defaults(&config);

    printf("PacketScope starting...\n");
    printf("Interface: %s\n",
           config.interface_name[0] == '\0' ? "default" : config.interface_name);
    printf("Max packets: %s\n",
           config.max_packets == 0 ? "unlimited" : "configured");

    return 0;
}
