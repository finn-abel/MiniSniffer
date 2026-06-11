#include <stdio.h>
#include <string.h>

#include "app_decoder.h"
#include "byte_reader.h"

#define HTTP_PORT 80
#define HTTP_ALT_PORT 8080
#define DNS_PORT 53
#define TLS_PORT 443
#define TLS_RECORD_HEADER_LEN 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16

/*
 * Always reset caller-owned AppInfo before attempting a decode so failed or
 * partial decodes cannot leave stale protocol metadata behind.
 */
static void app_info_clear(AppInfo *out) {
    if (out == NULL) {
        return;
    }

    memset(out, 0, sizeof(*out));
    out->protocol = APP_PROTO_UNKNOWN;
}

static void app_info_set(AppInfo *out, AppProtocol protocol, const char *summary) {
    if (out == NULL) {
        return;
    }

    app_info_clear(out);
    out->protocol = protocol;
    if (summary != NULL) {
        snprintf(out->summary, sizeof(out->summary), "%s", summary);
    }
}

static int port_matches(const PacketInfo *packet, uint16_t port) {
    return packet->has_ports != 0 &&
           (packet->src_port == port || packet->dst_port == port);
}

static int buffer_has_prefix(const uint8_t *data, size_t length, const char *prefix) {
    size_t prefix_length = strlen(prefix);

    return length >= prefix_length &&
           memcmp(data, prefix, prefix_length) == 0;
}

static int buffer_has_partial_prefix(const uint8_t *data, size_t length, const char *prefix) {
    size_t prefix_length = strlen(prefix);

    return length > 0 &&
           length < prefix_length &&
           memcmp(data, prefix, length) == 0;
}

/*
 * HTTP/1.x starts with a small set of ASCII request methods or HTTP/ for
 * responses. Partial prefixes return NEED_MORE so split TCP packets can be
 * completed by future stream reassembly.
 */
static AppDecodeResult decode_http_signature(
    const uint8_t *data,
    size_t length,
    AppInfo *out
) {
    static const char *const prefixes[] = {
        "GET ",
        "POST ",
        "PUT ",
        "DELETE ",
        "HEAD ",
        "OPTIONS ",
        "PATCH ",
        "TRACE ",
        "CONNECT ",
        "HTTP/"
    };
    size_t i;

    if (data == NULL || length == 0) {
        return APP_DECODE_NEED_MORE;
    }

    for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        if (buffer_has_prefix(data, length, prefixes[i])) {
            app_info_set(out, APP_PROTO_HTTP, "HTTP/1.x");
            return APP_DECODE_OK;
        }
        if (buffer_has_partial_prefix(data, length, prefixes[i])) {
            return APP_DECODE_NEED_MORE;
        }
    }

    return APP_DECODE_NO_MATCH;
}

/*
 * DNS messages have a fixed 12-byte header before variable-length names.
 * Full DNS question/answer parsing is added later, but this validates the
 * minimum bounded read path now.
 */
static AppDecodeResult decode_dns_signature(
    const uint8_t *data,
    size_t length,
    AppInfo *out
) {
    ByteReader reader;
    uint16_t ignored;

    if (data == NULL || length == 0) {
        return APP_DECODE_NEED_MORE;
    }
    if (length < 12) {
        return APP_DECODE_NEED_MORE;
    }

    br_init(&reader, data, length);
    if (!br_read_u16_be(&reader, &ignored) ||
        !br_read_u16_be(&reader, &ignored) ||
        !br_read_u16_be(&reader, &ignored) ||
        !br_read_u16_be(&reader, &ignored) ||
        !br_read_u16_be(&reader, &ignored) ||
        !br_read_u16_be(&reader, &ignored)) {
        return APP_DECODE_NEED_MORE;
    }

    app_info_set(out, APP_PROTO_DNS, "DNS message");
    return APP_DECODE_OK;
}

/*
 * TLS records begin with a five-byte header. ClientHello metadata can be split
 * across TCP packets, so a plausible but incomplete record returns NEED_MORE.
 */
static AppDecodeResult decode_tls_signature(
    const uint8_t *data,
    size_t length,
    AppInfo *out
) {
    ByteReader reader;
    uint8_t content_type;
    uint16_t record_version;
    uint16_t record_length;

    if (data == NULL || length == 0) {
        return APP_DECODE_NEED_MORE;
    }
    if (length < TLS_RECORD_HEADER_LEN) {
        if (data[0] == TLS_HANDSHAKE_CONTENT_TYPE) {
            return APP_DECODE_NEED_MORE;
        }
        return APP_DECODE_NO_MATCH;
    }

    br_init(&reader, data, length);
    if (!br_read_u8(&reader, &content_type) ||
        !br_read_u16_be(&reader, &record_version) ||
        !br_read_u16_be(&reader, &record_length)) {
        return APP_DECODE_NEED_MORE;
    }

    if (content_type != TLS_HANDSHAKE_CONTENT_TYPE ||
        (record_version >> 8) != 0x03) {
        return APP_DECODE_NO_MATCH;
    }
    if (length < TLS_RECORD_HEADER_LEN + (size_t)record_length) {
        return APP_DECODE_NEED_MORE;
    }

    app_info_set(out, APP_PROTO_TLS, "TLS ClientHello candidate");
    return APP_DECODE_OK;
}

/*
 * When a caller selected a preferred protocol from ports, a non-matching
 * payload is malformed for that protocol rather than an unclassified sniff miss.
 */
static AppDecodeResult preferred_result(
    AppDecodeResult result,
    AppProtocol preferred
) {
    if (result == APP_DECODE_NO_MATCH && preferred != APP_PROTO_UNKNOWN) {
        return APP_DECODE_MALFORMED;
    }

    return result;
}

/*
 * Buffer decoding is protocol-agnostic and does not depend on PacketInfo.
 * Future stream reassembly can pass assembled bytes here directly.
 */
AppDecodeResult app_decode_buffer(
    AppProtocol preferred,
    const uint8_t *data,
    size_t length,
    AppInfo *out
) {
    AppDecodeResult result;

    app_info_clear(out);

    if (data == NULL) {
        return APP_DECODE_NO_MATCH;
    }
    if (length == 0) {
        return preferred == APP_PROTO_UNKNOWN ? APP_DECODE_NO_MATCH : APP_DECODE_NEED_MORE;
    }

    if (preferred == APP_PROTO_HTTP || preferred == APP_PROTO_UNKNOWN) {
        result = decode_http_signature(data, length, out);
        if (result != APP_DECODE_NO_MATCH || preferred == APP_PROTO_HTTP) {
            return preferred_result(result, preferred);
        }
    }

    if (preferred == APP_PROTO_TLS || preferred == APP_PROTO_UNKNOWN) {
        result = decode_tls_signature(data, length, out);
        if (result != APP_DECODE_NO_MATCH || preferred == APP_PROTO_TLS) {
            return preferred_result(result, preferred);
        }
    }

    if (preferred == APP_PROTO_DNS) {
        return preferred_result(decode_dns_signature(data, length, out), preferred);
    }

    return APP_DECODE_NO_MATCH;
}

/*
 * Packet decoding chooses a preferred protocol from common ports, then hands
 * only the bounded decode window to the reusable buffer decoder.
 */
AppDecodeResult app_decode_packet(
    const PacketInfo *packet,
    AppInfo *out
) {
    AppProtocol preferred = APP_PROTO_UNKNOWN;

    app_info_clear(out);

    if (packet == NULL ||
        packet->has_payload == 0 ||
        packet->payload == NULL ||
        packet->payload_decode_length == 0) {
        return APP_DECODE_NO_MATCH;
    }

    if (port_matches(packet, HTTP_PORT) || port_matches(packet, HTTP_ALT_PORT)) {
        preferred = APP_PROTO_HTTP;
    } else if (port_matches(packet, DNS_PORT)) {
        preferred = APP_PROTO_DNS;
    } else if (port_matches(packet, TLS_PORT)) {
        preferred = APP_PROTO_TLS;
    }

    return app_decode_buffer(preferred,
                             packet->payload,
                             packet->payload_decode_length,
                             out);
}
