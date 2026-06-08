#include <stdio.h>

#include "common.h"

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

int main(void) {
    printf("PacketScope starting...\n");
    printf("Planned protocol support: %s, %s, %s\n",
           protocol_to_string(PROTO_TCP),
           protocol_to_string(PROTO_UDP),
           protocol_to_string(PROTO_ICMP));

    return 0;
}