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
    config->payload_decode_bytes = PACKETSCOPE_DEFAULT_PAYLOAD_DECODE_BYTES;
    config->payload_preview_bytes = PACKETSCOPE_DEFAULT_PAYLOAD_PREVIEW_BYTES;
    config->max_flows = PACKETSCOPE_DEFAULT_MAX_FLOWS;
    config->stream_buffer_bytes = PACKETSCOPE_DEFAULT_STREAM_BUFFER_BYTES;
    config->flow_timeout_seconds = PACKETSCOPE_DEFAULT_FLOW_TIMEOUT_SECONDS;
    config->max_packets = 0;
    config->stats_mode = 0;
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
    config->payload_display_enabled = 0;
    config->logging_enabled = 0;
    config->log_path[0] = '\0';
}
