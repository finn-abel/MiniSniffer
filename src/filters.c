#include <string.h>
#ifdef MINISNIFFER_WITH_LIBIDN2
#include <stdlib.h>
#include <idn2.h>
#endif

#include "filters.h"

/*
 * Transport-level filters are unchanged from the packet-only pipeline.
 * They run before app filters so ordinary packet filtering stays cheap.
 */
static int protocol_filter_matches(const AppConfig *config, const PacketInfo *info) {
    if (config->filter_protocol_enabled == 0) {
        return 1;
    }

    return info->protocol == config->filter_protocol;
}

static int port_filter_matches(const AppConfig *config, const PacketInfo *info) {
    if (config->filter_port_enabled == 0) {
        return 1;
    }
    if (info->has_ports == 0) {
        return 0;
    }

    return info->src_port == config->filter_port || info->dst_port == config->filter_port;
}

static int host_filter_matches(const AppConfig *config, const PacketInfo *info) {
    if (config->filter_host_enabled == 0) {
        return 1;
    }

    return strcmp(info->src_ip, config->filter_host) == 0 ||
           strcmp(info->dst_ip, config->filter_host) == 0;
}

/*
 * Payload filters inspect the bounded decode window. This keeps them aligned
 * with app decoder input instead of the smaller display preview.
 */
static int payload_contains(const unsigned char *payload, size_t payload_length,
                            const unsigned char *needle, size_t needle_length) {
    size_t i;

    if (payload == NULL || needle == NULL || needle_length == 0) {
        return 0;
    }
    if (payload_length < needle_length) {
        return 0;
    }

    for (i = 0; i <= payload_length - needle_length; i++) {
        if (memcmp(payload + i, needle, needle_length) == 0) {
            return 1;
        }
    }

    return 0;
}

static int payload_text_filter_matches(const AppConfig *config, const PacketInfo *info) {
    if (config->filter_payload_text_enabled == 0) {
        return 1;
    }
    if (info->has_payload == 0) {
        return 0;
    }

    return payload_contains(info->payload, info->payload_decode_length, config->filter_payload_text,
                            config->filter_payload_text_length);
}

static int payload_hex_filter_matches(const AppConfig *config, const PacketInfo *info) {
    if (config->filter_payload_hex_enabled == 0) {
        return 1;
    }
    if (info->has_payload == 0) {
        return 0;
    }

    return payload_contains(info->payload, info->payload_decode_length, config->filter_payload_hex,
                            config->filter_payload_hex_length);
}

/*
 * ALPN metadata is stored as a comma-separated list. Match whole list elements
 * so filtering for "h2" does not accidentally match part of another token.
 */
static int app_has_alpn(const char *list, const char *needle) {
    size_t needle_length;
    const char *cursor;

    if (list == NULL || needle == NULL || needle[0] == '\0') {
        return 0;
    }
    needle_length = strlen(needle);
    cursor = list;

    while (*cursor != '\0') {
        const char *end = strchr(cursor, ',');
        size_t length = end == NULL ? strlen(cursor) : (size_t)(end - cursor);

        if (length == needle_length && memcmp(cursor, needle, needle_length) == 0) {
            return 1;
        }
        if (end == NULL) {
            break;
        }
        cursor = end + 1;
    }

    return 0;
}

static unsigned char ascii_lower(unsigned char value) {
    return value >= 'A' && value <= 'Z' ? (unsigned char)(value + ('a' - 'A')) : value;
}

static int domain_name_equals_normalized(const char *left, const char *right) {
    size_t left_length;
    size_t right_length;
    size_t i;

    if (left == NULL || right == NULL) {
        return 0;
    }

    left_length = strlen(left);
    right_length = strlen(right);
    if (left_length > 1 && left[left_length - 1] == '.') {
        left_length--;
    }
    if (right_length > 1 && right[right_length - 1] == '.') {
        right_length--;
    }
    if (left_length != right_length) {
        return 0;
    }

    for (i = 0; i < left_length; i++) {
        if (ascii_lower((unsigned char)left[i]) != ascii_lower((unsigned char)right[i])) {
            return 0;
        }
    }
    return 1;
}

#ifdef MINISNIFFER_WITH_LIBIDN2
static int domain_name_equals_idna(const char *left, const char *right) {
    char *left_ascii = NULL;
    char *right_ascii = NULL;
    int matches = 0;

    if (left == NULL || right == NULL) {
        return 0;
    }
    if (idn2_lookup_u8((const uint8_t *)left, (uint8_t **)&left_ascii, IDN2_NFC_INPUT) != IDN2_OK ||
        idn2_lookup_u8((const uint8_t *)right, (uint8_t **)&right_ascii, IDN2_NFC_INPUT) !=
            IDN2_OK) {
        free(left_ascii);
        free(right_ascii);
        return 0;
    }

    matches = domain_name_equals_normalized(left_ascii, right_ascii);
    free(left_ascii);
    free(right_ascii);
    return matches;
}
#endif

static int domain_name_matches(const AppConfig *config, const char *left, const char *right) {
    if (left == NULL || right == NULL) {
        return 0;
    }
    if (config->domain_match_mode == DOMAIN_MATCH_EXACT) {
        return strcmp(left, right) == 0;
    }
#ifdef MINISNIFFER_WITH_LIBIDN2
    if (config->domain_match_mode == DOMAIN_MATCH_IDNA) {
        return domain_name_equals_idna(left, right);
    }
#endif

    return domain_name_equals_normalized(left, right);
}

/*
 * Checks one AppInfo object against all enabled app filters.
 * Protocol-specific filters fail when the app protocol does not match.
 */
static int app_filter_matches_one(const AppConfig *config, const AppInfo *app) {
    if (app == NULL || app->protocol == APP_PROTO_UNKNOWN) {
        return 0;
    }
    if (config->filter_app_enabled && app->protocol != config->filter_app_protocol) {
        return 0;
    }
    if (config->filter_http_host_enabled &&
        (app->protocol != APP_PROTO_HTTP ||
         !domain_name_matches(config, app->http_host, config->filter_http_host))) {
        return 0;
    }
    if (config->filter_http_method_enabled &&
        (app->protocol != APP_PROTO_HTTP ||
         strcmp(app->http_method, config->filter_http_method) != 0)) {
        return 0;
    }
    /*
     * mDNS is wire-compatible with DNS and reuses the same dns_query_name /
     * dns_query_type fields, so the DNS query/type filters apply to both.
     */
    if (config->filter_dns_query_enabled &&
        ((app->protocol != APP_PROTO_DNS && app->protocol != APP_PROTO_MDNS) ||
         !domain_name_matches(config, app->dns_query_name, config->filter_dns_query))) {
        return 0;
    }
    if (config->filter_dns_type_enabled &&
        ((app->protocol != APP_PROTO_DNS && app->protocol != APP_PROTO_MDNS) ||
         app->dns_query_type != config->filter_dns_type)) {
        return 0;
    }
    if (config->filter_tls_sni_enabled &&
        (app->protocol != APP_PROTO_TLS ||
         !domain_name_matches(config, app->tls_sni, config->filter_tls_sni))) {
        return 0;
    }
    if (config->filter_tls_alpn_enabled &&
        (app->protocol != APP_PROTO_TLS || !app_has_alpn(app->tls_alpn, config->filter_tls_alpn))) {
        return 0;
    }
    if (config->filter_dhcp_type_enabled &&
        (app->protocol != APP_PROTO_DHCP || app->dhcp_message_type != config->filter_dhcp_type)) {
        return 0;
    }
    if (config->filter_quic_version_enabled &&
        (app->protocol != APP_PROTO_QUIC || app->quic_version != config->filter_quic_version)) {
        return 0;
    }

    return 1;
}

/*
 * App filters are optional and are treated as an AND group when present.
 */
static int app_filters_enabled(const AppConfig *config) {
    return config->filter_app_enabled || config->filter_http_host_enabled ||
           config->filter_http_method_enabled || config->filter_dns_query_enabled ||
           config->filter_dns_type_enabled || config->filter_tls_sni_enabled ||
           config->filter_tls_alpn_enabled || config->filter_dhcp_type_enabled ||
           config->filter_quic_version_enabled;
}

/*
 * Packet-local mode uses only packet_app. Reassembly mode uses only already
 * classified flow_app, which means packets seen before classification do not
 * pass app filters and are not buffered for later replay.
 */
static int app_filters_match(const AppConfig *config, const FilterContext *context) {
    if (!app_filters_enabled(config)) {
        return 1;
    }
    if (config->reassemble) {
        return context->flow_is_classified && app_filter_matches_one(config, context->flow_app);
    }
    if (app_filter_matches_one(config, context->packet_app)) {
        return 1;
    }

    return 0;
}

/*
 * Filters use AND logic across packet, payload, packet-app, and future flow-app
 * metadata. Null contexts fail closed.
 */
bool filters_match(const AppConfig *config, const FilterContext *context) {
    const PacketInfo *info;

    if (config == NULL || context == NULL || context->packet == NULL) {
        return false;
    }

    info = context->packet;
    return protocol_filter_matches(config, info) && port_filter_matches(config, info) &&
           host_filter_matches(config, info) && payload_text_filter_matches(config, info) &&
           payload_hex_filter_matches(config, info) && app_filters_match(config, context);
}
