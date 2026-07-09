#ifndef APP_QUIC_H
#define APP_QUIC_H

#include <stddef.h>
#include <stdint.h>

#include "app_decoder.h"
#include "common.h"

/*
 * Decodes conservative metadata from a QUIC long-header Initial packet:
 * version, Destination Connection ID, and Source Connection ID only. QUIC
 * payloads are encrypted from the packet number onward; MiniSniffer never
 * attempts to remove header protection or decrypt anything, so parsing
 * intentionally stops right after the Source Connection ID.
 */
AppDecodeResult app_quic_decode_initial(const uint8_t *data, size_t length, AppInfo *out);

#endif
