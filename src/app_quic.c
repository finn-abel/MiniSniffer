#include <stdio.h>
#include <string.h>

#include "app_quic.h"

#define QUIC_HEADER_FORM_LONG_MASK 0xc0
#define QUIC_HEADER_FORM_LONG_VALUE 0xc0
#define QUIC_LONG_PACKET_TYPE_MASK 0x30
#define QUIC_LONG_PACKET_TYPE_INITIAL 0x00
#define QUIC_MAX_CONNECTION_ID_LEN MINISNIFFER_QUIC_CID_MAX_BYTES

/*
 * QUIC parsing only records clear Initial-packet metadata. Clear AppInfo on
 * failure so encrypted or malformed traffic leaves app protocol UNKNOWN
 * upstream, matching the TLS and DNS decoders.
 */
static void clear_app_info(AppInfo *out) {
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
        out->protocol = APP_PROTO_UNKNOWN;
    }
}

static int remaining(size_t length, size_t offset, size_t needed) {
    return offset <= length && needed <= length - offset;
}

static int read_u8_at(const uint8_t *data, size_t length, size_t *offset, uint8_t *out) {
    if (!remaining(length, *offset, 1)) {
        return 1;
    }
    *out = data[*offset];
    (*offset)++;
    return 0;
}

static int read_u32_at(const uint8_t *data, size_t length, size_t *offset, uint32_t *out) {
    if (!remaining(length, *offset, 4)) {
        return 1;
    }
    *out = ((uint32_t)data[*offset] << 24) | ((uint32_t)data[*offset + 1] << 16) |
           ((uint32_t)data[*offset + 2] << 8) | data[*offset + 3];
    *offset += 4;
    return 0;
}

static void format_hex(const uint8_t *bytes, size_t length, char *out, size_t out_size) {
    size_t i;
    size_t written = 0;

    out[0] = '\0';
    for (i = 0; i < length; i++) {
        if (written + 2 >= out_size) {
            break;
        }
        written += (size_t)snprintf(out + written, out_size - written, "%02x", bytes[i]);
    }
}

/*
 * Connection IDs are a one-byte length followed by that many raw bytes, the
 * same shape as a TLS length-prefixed vector.
 */
static AppDecodeResult read_connection_id(const uint8_t *data, size_t length, size_t *offset,
                                          char *out_text, size_t out_text_size) {
    uint8_t id_length;

    if (read_u8_at(data, length, offset, &id_length) != 0) {
        return APP_DECODE_NEED_MORE;
    }
    if (id_length > QUIC_MAX_CONNECTION_ID_LEN) {
        return APP_DECODE_MALFORMED;
    }
    if (!remaining(length, *offset, id_length)) {
        return APP_DECODE_NEED_MORE;
    }
    format_hex(data + *offset, id_length, out_text, out_text_size);
    *offset += id_length;
    return APP_DECODE_OK;
}

/*
 * MiniSniffer decodes only the visible, unencrypted prefix of a QUIC long
 * header Initial packet: flags, version, Destination Connection ID, and
 * Source Connection ID. Token, Length, packet number, and payload either
 * require removing header protection or are encrypted outright, so parsing
 * intentionally stops right after the Source Connection ID.
 */
AppDecodeResult app_quic_decode_initial(const uint8_t *data, size_t length, AppInfo *out) {
    size_t offset = 0;
    uint8_t first_byte;
    AppDecodeResult result;

    clear_app_info(out);
    if (data == NULL || length == 0) {
        return APP_DECODE_NO_MATCH;
    }
    if (read_u8_at(data, length, &offset, &first_byte) != 0) {
        return APP_DECODE_NEED_MORE;
    }
    if ((first_byte & QUIC_HEADER_FORM_LONG_MASK) != QUIC_HEADER_FORM_LONG_VALUE) {
        return APP_DECODE_NO_MATCH;
    }
    if ((first_byte & QUIC_LONG_PACKET_TYPE_MASK) != QUIC_LONG_PACKET_TYPE_INITIAL) {
        /* Only Initial packets are decoded; 0-RTT/Handshake/Retry are ignored. */
        return APP_DECODE_NO_MATCH;
    }

    if (read_u32_at(data, length, &offset, &out->quic_version) != 0) {
        return APP_DECODE_NEED_MORE;
    }
    if (out->quic_version == 0) {
        /* Version 0 marks a Version Negotiation packet, a different format. */
        return APP_DECODE_NO_MATCH;
    }
    out->protocol = APP_PROTO_QUIC;

    result = read_connection_id(data, length, &offset, out->quic_dcid, sizeof(out->quic_dcid));
    if (result != APP_DECODE_OK) {
        clear_app_info(out);
        return result;
    }
    result = read_connection_id(data, length, &offset, out->quic_scid, sizeof(out->quic_scid));
    if (result != APP_DECODE_OK) {
        clear_app_info(out);
        return result;
    }

    snprintf(out->summary, sizeof(out->summary), "QUIC Initial version=0x%08x dcid=%s scid=%s",
             (unsigned int)out->quic_version, out->quic_dcid, out->quic_scid);
    return APP_DECODE_OK;
}
