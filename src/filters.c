#include <string.h>

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

    return info->src_port == config->filter_port ||
           info->dst_port == config->filter_port;
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
static int payload_contains(
    const unsigned char *payload,
    size_t payload_length,
    const unsigned char *needle,
    size_t needle_length
) {
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

    return payload_contains(info->payload,
                            info->payload_decode_length,
                            config->filter_payload_text,
                            config->filter_payload_text_length);
}

static int payload_hex_filter_matches(const AppConfig *config, const PacketInfo *info) {
    if (config->filter_payload_hex_enabled == 0) {
        return 1;
    }
    if (info->has_payload == 0) {
        return 0;
    }

    return payload_contains(info->payload,
                            info->payload_decode_length,
                            config->filter_payload_hex,
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
         strcmp(app->http_host, config->filter_http_host) != 0)) {
        return 0;
    }
    if (config->filter_http_method_enabled &&
        (app->protocol != APP_PROTO_HTTP ||
         strcmp(app->http_method, config->filter_http_method) != 0)) {
        return 0;
    }
    if (config->filter_dns_query_enabled &&
        (app->protocol != APP_PROTO_DNS ||
         strcmp(app->dns_query_name, config->filter_dns_query) != 0)) {
        return 0;
    }
    if (config->filter_dns_type_enabled &&
        (app->protocol != APP_PROTO_DNS ||
         app->dns_query_type != config->filter_dns_type)) {
        return 0;
    }
    if (config->filter_tls_sni_enabled &&
        (app->protocol != APP_PROTO_TLS ||
         strcmp(app->tls_sni, config->filter_tls_sni) != 0)) {
        return 0;
    }
    if (config->filter_tls_alpn_enabled &&
        (app->protocol != APP_PROTO_TLS ||
         !app_has_alpn(app->tls_alpn, config->filter_tls_alpn))) {
        return 0;
    }

    return 1;
}

/*
 * App filters are optional and are treated as an AND group when present.
 */
static int app_filters_enabled(const AppConfig *config) {
    return config->filter_app_enabled ||
           config->filter_http_host_enabled ||
           config->filter_http_method_enabled ||
           config->filter_dns_query_enabled ||
           config->filter_dns_type_enabled ||
           config->filter_tls_sni_enabled ||
           config->filter_tls_alpn_enabled;
}

/*
 * Packet-local metadata is authoritative now. Flow metadata is accepted through
 * the same matcher so later stream-aware classification can pass future packets.
 */
static int app_filters_match(const AppConfig *config, const FilterContext *context) {
    if (!app_filters_enabled(config)) {
        return 1;
    }
    if (app_filter_matches_one(config, context->packet_app)) {
        return 1;
    }
    if (context->flow_is_classified && app_filter_matches_one(config, context->flow_app)) {
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
    return protocol_filter_matches(config, info) &&
           port_filter_matches(config, info) &&
           host_filter_matches(config, info) &&
           payload_text_filter_matches(config, info) &&
           payload_hex_filter_matches(config, info) &&
           app_filters_match(config, context);
}
