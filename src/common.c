#include <string.h>

#include "common.h"

const char *protocol_to_string(Protocol protocol) {
    /* Keep protocol display strings lowercase to match accepted CLI values. */
    switch (protocol) {
        case PROTO_IPV4:
            return "IPv4";
        case PROTO_TCP:
            return "tcp";
        case PROTO_UDP:
            return "udp";
        case PROTO_ICMP:
            return "icmp";
        case PROTO_OTHER:
        default:
            return "other";
    }
}

int protocol_from_string(const char *text, Protocol *protocol) {
    /* Reject null inputs before comparing against supported protocol names. */
    if (text == NULL || protocol == NULL) {
        return 1;
    }

    if (strcmp(text, "tcp") == 0) {
        *protocol = PROTO_TCP;
        return 0;
    }
    if (strcmp(text, "udp") == 0) {
        *protocol = PROTO_UDP;
        return 0;
    }
    if (strcmp(text, "icmp") == 0) {
        *protocol = PROTO_ICMP;
        return 0;
    }
    if (strcmp(text, "other") == 0) {
        *protocol = PROTO_OTHER;
        return 0;
    }

    return 1;
}
