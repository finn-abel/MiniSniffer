
#ifndef COMMON_H
#define COMMON_H

typedef enum {
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_OTHER
} Protocol;

const char *protocol_to_string(Protocol protocol);

#endif