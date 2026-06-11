#ifndef APP_DECODER_H
#define APP_DECODER_H

#include <stddef.h>
#include <stdint.h>

#include "common.h"

/*
 * AppDecodeResult describes packet-local and stream-aware decode outcomes.
 * NEED_MORE is returned when the bytes look like a supported protocol but the
 * current buffer is too short to finish safely.
 */
typedef enum {
    APP_DECODE_NO_MATCH = 0,
    APP_DECODE_OK,
    APP_DECODE_NEED_MORE,
    APP_DECODE_MALFORMED
} AppDecodeResult;

/*
 * Decodes application metadata from a parsed packet.
 * Uses packet ports and payload signatures to choose a likely decoder.
 * Reads only PacketInfo's bounded payload_decode_length window.
 */
AppDecodeResult app_decode_packet(
    const PacketInfo *packet,
    AppInfo *out
);

/*
 * Decodes application metadata from an arbitrary byte buffer.
 * preferred can force one protocol or APP_PROTO_UNKNOWN to sniff signatures.
 * This is the reusable core for future TCP stream reassembly.
 */
AppDecodeResult app_decode_buffer(
    AppProtocol preferred,
    const uint8_t *data,
    size_t length,
    AppInfo *out
);

/*
 * Decodes reassembled TCP stream bytes using packet ports as framing hints.
 * DNS-over-TCP keeps its two-byte length prefix here, while HTTP and TLS use
 * the same buffer decoders as packet-local decoding.
 */
AppDecodeResult app_decode_stream(
    const PacketInfo *packet,
    const uint8_t *data,
    size_t length,
    AppInfo *out
);

#endif
