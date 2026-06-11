#include <string.h>

#include "filter.h"

/*
 * Protocol filtering is optional.
 * When enabled, the parsed packet protocol must exactly match the requested one.
 */
static int protocol_filter_matches(const AppConfig *config, const PacketInfo *info) {
    if (config->filter_protocol_enabled == 0) {
        return 1;
    }

    return info->protocol == config->filter_protocol;
}

/*
 * Port filtering applies only to packets with transport ports.
 * A packet matches when either source or destination port equals the requested port.
 */
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

/*
 * Host filtering compares the configured IPv4 string against both endpoints.
 * Parser-owned empty strings naturally fail when a host filter is enabled.
 */
static int host_filter_matches(const AppConfig *config, const PacketInfo *info) {
    if (config->filter_host_enabled == 0) {
        return 1;
    }

    return strcmp(info->src_ip, config->filter_host) == 0 ||
           strcmp(info->dst_ip, config->filter_host) == 0;
}

/*
 * Binary-safe substring search over the bounded payload decode window.
 * Do not use strstr here: packet payloads may contain null bytes.
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

    /* The <= form is safe because payload_length >= needle_length above. */
    for (i = 0; i <= payload_length - needle_length; i++) {
        if (memcmp(payload + i, needle, needle_length) == 0) {
            return 1;
        }
    }

    return 0;
}

/*
 * Text payload filters are literal byte filters.
 * They intentionally do not do case folding or encoding conversion.
 */
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

/*
 * Hex payload filters share the same byte-search path as text filters after
 * the CLI has decoded the user's hex pattern into raw bytes.
 */
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
 * A packet is displayable only if every enabled filter accepts it.
 * Null inputs are treated as non-matches to keep callers simple and safe.
 */
int filter_packet_matches(const AppConfig *config, const PacketInfo *info) {
    if (config == NULL || info == NULL) {
        return 0;
    }

    /*
     * Filters use AND logic: each enabled filter gets a chance to reject
     * the packet before it is displayed or counted.
     */
    return protocol_filter_matches(config, info) &&
           port_filter_matches(config, info) &&
           host_filter_matches(config, info) &&
           payload_text_filter_matches(config, info) &&
           payload_hex_filter_matches(config, info);
}
