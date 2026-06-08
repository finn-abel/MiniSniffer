#include <string.h>

#include "parser.h"

int parser_parse_packet(
    const unsigned char *packet,
    size_t packet_len,
    PacketInfo *info
) {
    (void)packet;

    if (info == NULL) {
        return 1;
    }

    /* Parser details come later; for now create a safe empty summary. */
    memset(info, 0, sizeof(*info));
    info->size = packet_len;
    info->protocol = PROTO_OTHER;
    info->src_ip[0] = '\0';
    info->dst_ip[0] = '\0';

    return 0;
}
