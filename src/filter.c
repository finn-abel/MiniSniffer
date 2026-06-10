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
           host_filter_matches(config, info);
}
