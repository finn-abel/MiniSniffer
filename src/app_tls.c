#include <stdio.h>
#include <string.h>

#include "app_tls.h"
#include "byte_reader.h"

#define TLS_RECORD_HANDSHAKE 0x16
#define TLS_HANDSHAKE_CLIENT_HELLO 0x01
#define TLS_RECORD_HEADER_LEN 5
#define TLS_HANDSHAKE_HEADER_LEN 4
#define TLS_EXT_SERVER_NAME 0x0000
#define TLS_EXT_ALPN 0x0010

/*
 * TLS parsing only records clear ClientHello metadata. Clear AppInfo on failure
 * so encrypted or malformed traffic leaves app protocol UNKNOWN upstream.
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

/*
 * These offset-based helpers are used inside already-bounded TLS vectors where
 * a ByteReader over the whole packet would not know the vector end.
 */
static int read_u8_at(const uint8_t *data, size_t length, size_t *offset, uint8_t *out) {
    if (!remaining(length, *offset, 1)) {
        return 1;
    }
    *out = data[*offset];
    (*offset)++;
    return 0;
}

static int read_u16_at(const uint8_t *data, size_t length, size_t *offset, uint16_t *out) {
    if (!remaining(length, *offset, 2)) {
        return 1;
    }
    *out = (uint16_t)(((uint16_t)data[*offset] << 8) | data[*offset + 1]);
    *offset += 2;
    return 0;
}

static int read_u24_at(const uint8_t *data, size_t length, size_t *offset, size_t *out) {
    if (!remaining(length, *offset, 3)) {
        return 1;
    }
    *out = ((size_t)data[*offset] << 16) |
           ((size_t)data[*offset + 1] << 8) |
           data[*offset + 2];
    *offset += 3;
    return 0;
}

static void copy_text(char *destination, size_t destination_size, const uint8_t *data, size_t length) {
    size_t copy_length;

    if (destination == NULL || destination_size == 0) {
        return;
    }
    copy_length = length;
    if (copy_length >= destination_size) {
        copy_length = destination_size - 1;
    }
    memcpy(destination, data, copy_length);
    destination[copy_length] = '\0';
}

/*
 * Server Name extension contains a list; MiniSniffer records the first host
 * name entry and ignores other name types.
 */
static int parse_sni_extension(const uint8_t *data, size_t length, AppInfo *out) {
    size_t offset = 0;
    size_t list_end;
    uint16_t list_length;

    if (read_u16_at(data, length, &offset, &list_length) != 0 ||
        list_length != length - offset) {
        return 1;
    }
    list_end = offset + list_length;

    while (offset < list_end) {
        uint8_t name_type;
        uint16_t name_length;

        if (read_u8_at(data, list_end, &offset, &name_type) != 0 ||
            read_u16_at(data, list_end, &offset, &name_length) != 0 ||
            name_length == 0 ||
            name_length > list_end - offset) {
            return 1;
        }
        if (name_type == 0 && out->tls_sni[0] == '\0') {
            copy_text(out->tls_sni, sizeof(out->tls_sni), data + offset, name_length);
        }
        offset += name_length;
    }

    return offset == list_end ? 0 : 1;
}

/*
 * ALPN can advertise multiple protocols. Store them as a bounded comma-separated
 * string for compact display/logging and future filtering.
 */
static int append_alpn(char *destination, size_t destination_size, const uint8_t *data, size_t length) {
    size_t current_length = strlen(destination);
    size_t copy_length = length;

    if (current_length != 0) {
        if (current_length + 1 >= destination_size) {
            return 1;
        }
        destination[current_length] = ',';
        current_length++;
        destination[current_length] = '\0';
    }
    if (current_length + copy_length >= destination_size) {
        copy_length = destination_size - current_length - 1;
    }
    memcpy(destination + current_length, data, copy_length);
    destination[current_length + copy_length] = '\0';
    return 0;
}

static int parse_alpn_extension(const uint8_t *data, size_t length, AppInfo *out) {
    size_t offset = 0;
    size_t list_end;
    uint16_t list_length;

    if (read_u16_at(data, length, &offset, &list_length) != 0 ||
        list_length != length - offset) {
        return 1;
    }
    list_end = offset + list_length;

    while (offset < list_end) {
        uint8_t protocol_length;

        if (read_u8_at(data, list_end, &offset, &protocol_length) != 0 ||
            protocol_length == 0 ||
            protocol_length > list_end - offset) {
            return 1;
        }
        if (append_alpn(out->tls_alpn,
                        sizeof(out->tls_alpn),
                        data + offset,
                        protocol_length) != 0) {
            return 1;
        }
        offset += protocol_length;
    }

    return offset == list_end ? 0 : 1;
}

/*
 * TLS extensions are length-delimited vectors. Unknown extensions are skipped,
 * while SNI and ALPN are decoded from their own bounded extension data.
 */
static int parse_extensions(const uint8_t *data, size_t length, size_t offset, AppInfo *out) {
    uint16_t extensions_length;
    size_t extensions_end;

    if (offset == length) {
        return 0;
    }
    if (read_u16_at(data, length, &offset, &extensions_length) != 0 ||
        extensions_length > length - offset) {
        return 1;
    }

    extensions_end = offset + extensions_length;
    while (offset < extensions_end) {
        uint16_t extension_type;
        uint16_t extension_length;
        const uint8_t *extension_data;

        if (read_u16_at(data, extensions_end, &offset, &extension_type) != 0 ||
            read_u16_at(data, extensions_end, &offset, &extension_length) != 0 ||
            extension_length > extensions_end - offset) {
            return 1;
        }

        extension_data = data + offset;
        if (extension_type == TLS_EXT_SERVER_NAME) {
            if (parse_sni_extension(extension_data, extension_length, out) != 0) {
                return 1;
            }
        } else if (extension_type == TLS_EXT_ALPN) {
            if (parse_alpn_extension(extension_data, extension_length, out) != 0) {
                return 1;
            }
        }
        offset += extension_length;
    }

    return offset == extensions_end ? 0 : 1;
}

/*
 * ClientHello body parsing follows the TLS vector order and stops at extensions.
 * Cipher suites and compression methods are validated for length only.
 */
static AppDecodeResult parse_client_hello_body(
    const uint8_t *data,
    size_t length,
    AppInfo *out
) {
    size_t offset = 0;
    uint8_t session_id_length;
    uint16_t vector_length;

    if (read_u16_at(data, length, &offset, &out->tls_client_version) != 0 ||
        !remaining(length, offset, 32)) {
        return APP_DECODE_MALFORMED;
    }
    offset += 32;

    if (read_u8_at(data, length, &offset, &session_id_length) != 0 ||
        !remaining(length, offset, session_id_length)) {
        return APP_DECODE_MALFORMED;
    }
    offset += session_id_length;

    if (read_u16_at(data, length, &offset, &vector_length) != 0 ||
        vector_length == 0 ||
        (vector_length % 2) != 0 ||
        !remaining(length, offset, vector_length)) {
        return APP_DECODE_MALFORMED;
    }
    offset += vector_length;

    if (read_u8_at(data, length, &offset, &session_id_length) != 0 ||
        session_id_length == 0 ||
        !remaining(length, offset, session_id_length)) {
        return APP_DECODE_MALFORMED;
    }
    offset += session_id_length;

    if (parse_extensions(data, length, offset, out) != 0) {
        return APP_DECODE_MALFORMED;
    }

    snprintf(out->summary,
             sizeof(out->summary),
             "TLS ClientHello sni=%s alpn=%s",
             out->tls_sni,
             out->tls_alpn);
    return APP_DECODE_OK;
}

/*
 * Decode only TLS handshake records carrying ClientHello. Other TLS records are
 * not errors; they are simply not useful for the plaintext metadata MiniSniffer
 * is allowed to inspect.
 */
AppDecodeResult app_tls_decode_client_hello(
    const uint8_t *data,
    size_t length,
    AppInfo *out
) {
    ByteReader reader;
    uint8_t content_type;
    uint16_t record_length;
    size_t offset = TLS_RECORD_HEADER_LEN;
    size_t handshake_length;

    clear_app_info(out);
    if (data == NULL || length == 0) {
        return APP_DECODE_NO_MATCH;
    }
    /*
     * A leading handshake content type is enough to know a stream buffer may
     * become TLS once more record-header bytes arrive.
     */
    if (length < TLS_RECORD_HEADER_LEN) {
        return data[0] == TLS_RECORD_HANDSHAKE ? APP_DECODE_NEED_MORE : APP_DECODE_NO_MATCH;
    }

    br_init(&reader, data, length);
    if (!br_read_u8(&reader, &content_type) ||
        !br_read_u16_be(&reader, &out->tls_record_version) ||
        !br_read_u16_be(&reader, &record_length)) {
        return APP_DECODE_NEED_MORE;
    }
    if (content_type != TLS_RECORD_HANDSHAKE || (out->tls_record_version >> 8) != 0x03) {
        return APP_DECODE_NO_MATCH;
    }
    /*
     * Record and handshake lengths may span TCP segments, so short but plausible
     * TLS returns NEED_MORE instead of MALFORMED.
     */
    if (length < TLS_RECORD_HEADER_LEN + (size_t)record_length) {
        return APP_DECODE_NEED_MORE;
    }
    if (record_length < TLS_HANDSHAKE_HEADER_LEN) {
        return APP_DECODE_MALFORMED;
    }

    out->protocol = APP_PROTO_TLS;
    if (read_u8_at(data, length, &offset, &out->tls_handshake_type) != 0 ||
        read_u24_at(data, length, &offset, &handshake_length) != 0) {
        clear_app_info(out);
        return APP_DECODE_NEED_MORE;
    }
    if (out->tls_handshake_type != TLS_HANDSHAKE_CLIENT_HELLO) {
        clear_app_info(out);
        return APP_DECODE_NO_MATCH;
    }
    if (handshake_length > (size_t)record_length - TLS_HANDSHAKE_HEADER_LEN) {
        clear_app_info(out);
        return APP_DECODE_NEED_MORE;
    }

    {
        AppDecodeResult result = parse_client_hello_body(data + offset, handshake_length, out);

        if (result != APP_DECODE_OK) {
            clear_app_info(out);
        }
        return result;
    }
}
