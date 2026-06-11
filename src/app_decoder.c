#include <string.h>

#include "app_decoder.h"
#include "app_dns.h"
#include "app_http.h"
#include "app_tls.h"

#define HTTP_PORT 80
#define HTTP_ALT_PORT 8080
#define HTTP_DEV_PORT 8000
#define DNS_PORT 53
#define TLS_PORT 443
#define TLS_ALT_PORT 8443
#define TLS_RECORD_HANDSHAKE 0x16

/*
 * Always reset caller-owned AppInfo before attempting a decode so failed or
 * partial decodes cannot leave stale protocol metadata behind.
 */
static void app_info_clear(AppInfo *out) {
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
        out->protocol = APP_PROTO_UNKNOWN;
    }
}

static int port_matches(const PacketInfo *packet, uint16_t port) {
    return packet->has_ports != 0 &&
           (packet->src_port == port || packet->dst_port == port);
}

/*
 * Signature helpers are intentionally shallow. They decide which full decoder
 * should get first chance without duplicating protocol parsing here.
 */
static int payload_starts_with(const uint8_t *data, size_t length, const char *prefix) {
    size_t prefix_length = strlen(prefix);

    return length >= prefix_length && memcmp(data, prefix, prefix_length) == 0;
}

static int payload_starts_with_http(const uint8_t *data, size_t length) {
    static const char *const prefixes[] = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
        "OPTIONS ", "PATCH ", "TRACE ", "CONNECT ", "HTTP/"
    };
    size_t i;

    for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        if (payload_starts_with(data, length, prefixes[i])) {
            return 1;
        }
    }

    return 0;
}

static int payload_starts_with_tls(const uint8_t *data, size_t length) {
    return length > 0 && data[0] == TLS_RECORD_HANDSHAKE;
}

/*
 * DNS headers alone are common in arbitrary binary data. Treat DNS as a sniffed
 * match only after the DNS decoder found a first question name.
 */
static int dns_decode_result_is_strong_match(AppDecodeResult result, const AppInfo *info) {
    return result == APP_DECODE_OK &&
           info != NULL &&
           info->protocol == APP_PROTO_DNS &&
           info->dns_question_count > 0 &&
           info->dns_query_name[0] != '\0';
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

    /*
     * Preferred protocols come from caller context such as ports or future flow
     * classification. In that mode, run only the selected decoder.
     */
    if (preferred == APP_PROTO_HTTP) {
        return preferred_result(app_http_decode(data, length, out), preferred);
    }
    if (preferred == APP_PROTO_TLS) {
        return preferred_result(app_tls_decode_client_hello(data, length, out), preferred);
    }
    if (preferred == APP_PROTO_DNS) {
        return preferred_result(app_dns_decode_message(data, length, out), preferred);
    }

    /*
     * Unknown buffers are sniffed in a conservative order. HTTP and TLS have
     * recognizable starts; DNS is accepted only when the decoded question is
     * strong enough to avoid classifying random bytes as DNS.
     */
    result = app_http_decode(data, length, out);
    if (result == APP_DECODE_OK || result == APP_DECODE_NEED_MORE) {
        return result;
    }

    result = app_tls_decode_client_hello(data, length, out);
    if (result == APP_DECODE_OK || result == APP_DECODE_NEED_MORE) {
        return result;
    }

    result = app_dns_decode_message(data, length, out);
    if (dns_decode_result_is_strong_match(result, out)) {
        return result;
    }
    app_info_clear(out);
    return APP_DECODE_NO_MATCH;
}

/*
 * Packet decoding chooses a preferred decoder from protocol and port hints.
 * Without strong hints it falls back to payload signatures and leaves AppInfo
 * UNKNOWN when no decoder succeeds.
 */
AppDecodeResult app_decode_packet(
    const PacketInfo *packet,
    AppInfo *out
) {
    AppDecodeResult result;

    app_info_clear(out);

    if (packet == NULL ||
        packet->has_payload == 0 ||
        packet->payload == NULL ||
        packet->payload_decode_length == 0) {
        return APP_DECODE_NO_MATCH;
    }

    /*
     * Packet-local hints are deliberately protocol-aware. For example, TCP/53
     * is DNS-over-TCP with a length prefix, while UDP/53 is a raw DNS message.
     */
    if (packet->protocol == PROTO_TCP &&
        (port_matches(packet, HTTP_PORT) ||
         port_matches(packet, HTTP_ALT_PORT) ||
         port_matches(packet, HTTP_DEV_PORT))) {
        return preferred_result(app_http_decode(packet->payload, packet->payload_decode_length, out),
                                APP_PROTO_HTTP);
    }
    if (packet->protocol == PROTO_TCP &&
        (port_matches(packet, TLS_PORT) || port_matches(packet, TLS_ALT_PORT))) {
        return preferred_result(app_tls_decode_client_hello(packet->payload,
                                                            packet->payload_decode_length,
                                                            out),
                                APP_PROTO_TLS);
    }
    if (packet->protocol == PROTO_UDP && port_matches(packet, DNS_PORT)) {
        return preferred_result(app_dns_decode_udp(packet->payload, packet->payload_decode_length, out),
                                APP_PROTO_DNS);
    }
    if (packet->protocol == PROTO_TCP && port_matches(packet, DNS_PORT)) {
        return preferred_result(app_dns_decode_tcp_frame(packet->payload,
                                                         packet->payload_decode_length,
                                                         out),
                                APP_PROTO_DNS);
    }

    if (payload_starts_with_http(packet->payload, packet->payload_decode_length)) {
        result = app_http_decode(packet->payload, packet->payload_decode_length, out);
        if (result != APP_DECODE_NO_MATCH) {
            return result;
        }
    }
    if (payload_starts_with_tls(packet->payload, packet->payload_decode_length)) {
        result = app_tls_decode_client_hello(packet->payload, packet->payload_decode_length, out);
        if (result != APP_DECODE_NO_MATCH) {
            return result;
        }
    }

    result = app_dns_decode_message(packet->payload, packet->payload_decode_length, out);
    if (dns_decode_result_is_strong_match(result, out)) {
        return result;
    }

    app_info_clear(out);
    return APP_DECODE_NO_MATCH;
}
