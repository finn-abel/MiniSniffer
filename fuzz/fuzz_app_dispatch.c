#include <string.h>

#include "app_decoder.h"
#include "fuzz_common.h"

static AppProtocol pick_preferred(uint8_t selector) {
    switch (selector % 7) {
    case 0:
        return APP_PROTO_UNKNOWN;
    case 1:
        return APP_PROTO_HTTP;
    case 2:
        return APP_PROTO_DNS;
    case 3:
        return APP_PROTO_TLS;
    case 4:
        return APP_PROTO_DHCP;
    case 5:
        return APP_PROTO_MDNS;
    default:
        return APP_PROTO_QUIC;
    }
}

static Protocol pick_transport(uint8_t selector) {
    switch (selector % 3) {
    case 0:
        return PROTO_TCP;
    case 1:
        return PROTO_UDP;
    default:
        return PROTO_OTHER;
    }
}

/*
 * Exercises the protocol/port dispatch logic itself (app_decode_buffer's
 * preferred-vs-sniffed paths, and app_decode_packet's port/protocol-based
 * decoder selection), not just one protocol's own parser. The first four
 * fuzz bytes pick a preferred protocol, a transport, and two port bytes;
 * the remainder is the payload handed to both dispatchers.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    AppInfo info;
    AppProtocol preferred;
    PacketInfo packet;

    if (size < 4) {
        return 0;
    }
    preferred = pick_preferred(data[0]);

    app_decode_buffer(preferred, data + 4, size - 4, &info);

    memset(&packet, 0, sizeof(packet));
    packet.protocol = pick_transport(data[1]);
    packet.has_ports = 1;
    packet.src_port = (uint16_t)(data[2] | ((uint16_t)data[3] << 8));
    packet.dst_port = (uint16_t)(data[3] | ((uint16_t)data[2] << 8));
    packet.has_payload = size > 4;
    packet.payload = data + 4;
    packet.payload_capture_length = size - 4;
    packet.payload_decode_length = size - 4;

    app_decode_packet(&packet, &info);
    return 0;
}
