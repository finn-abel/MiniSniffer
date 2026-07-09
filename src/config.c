#include <string.h>

#include "config.h"

void config_init_defaults(AppConfig *config) {
    if (config == NULL) {
        return;
    }

    /* Zero first so disabled filters and empty strings have predictable values. */
    memset(config, 0, sizeof(*config));

    /* Empty interface means "choose the default device" at capture setup time. */
    config->interface_name[0] = '\0';
    config->decode_app = false;
    config->reassemble = false;
    config->payload_decode_bytes = MINISNIFFER_DEFAULT_PAYLOAD_DECODE_BYTES;
    config->payload_preview_bytes = MINISNIFFER_DEFAULT_PAYLOAD_PREVIEW_BYTES;
    config->max_flows = MINISNIFFER_DEFAULT_MAX_FLOWS;
    config->stream_buffer_bytes = MINISNIFFER_DEFAULT_STREAM_BUFFER_BYTES;
    config->flow_timeout_seconds = MINISNIFFER_DEFAULT_FLOW_TIMEOUT_SECONDS;
    config->ipv4_fragment_max_datagrams = MINISNIFFER_DEFAULT_IPV4_FRAGMENT_MAX_DATAGRAMS;
    config->ipv4_fragment_max_bytes = MINISNIFFER_DEFAULT_IPV4_FRAGMENT_MAX_BYTES;
    config->ipv4_fragment_timeout_seconds = MINISNIFFER_DEFAULT_IPV4_FRAGMENT_TIMEOUT_SECONDS;
    config->max_packets = 0;
    config->stats_mode = 0;
    config->version_requested = false;
    config->list_interfaces = false;
    config->quiet = false;
    config->verbose = false;
    config->color_enabled = true;
    config->json_output = false;
    config->log_flush_mode = LOG_FLUSH_LINE;
    config->read_path_enabled = false;
    config->read_path[0] = '\0';
    config->write_path_enabled = false;
    config->write_path[0] = '\0';
    config->no_bpf = false;
    config->filter_protocol_enabled = 0;
    config->filter_protocol = PROTO_OTHER;
    config->filter_port_enabled = 0;
    config->filter_port = 0;
    config->filter_host_enabled = 0;
    config->filter_host[0] = '\0';
    config->filter_payload_text_enabled = 0;
    config->filter_payload_text_length = 0;
    config->filter_payload_hex_enabled = 0;
    config->filter_payload_hex_length = 0;
    config->filter_app_enabled = false;
    config->filter_app_protocol = APP_PROTO_UNKNOWN;
    config->filter_http_host_enabled = false;
    config->filter_http_host[0] = '\0';
    config->filter_http_method_enabled = false;
    config->filter_http_method[0] = '\0';
    config->filter_dns_query_enabled = false;
    config->filter_dns_query[0] = '\0';
    config->filter_dns_type_enabled = false;
    config->filter_dns_type = 0;
    config->filter_tls_sni_enabled = false;
    config->filter_tls_sni[0] = '\0';
    config->filter_tls_alpn_enabled = false;
    config->filter_tls_alpn[0] = '\0';
    config->domain_match_mode = DOMAIN_MATCH_NORMALIZED;
    config->filter_dhcp_type_enabled = false;
    config->filter_dhcp_type = 0;
    config->filter_quic_version_enabled = false;
    config->filter_quic_version = 0;
    config->payload_display_enabled = 0;
    config->logging_enabled = 0;
    config->log_path[0] = '\0';
}
