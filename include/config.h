#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#include "common.h"

#define PACKETSCOPE_MAX_PAYLOAD_PATTERN_BYTES 128
#define PACKETSCOPE_DEFAULT_PAYLOAD_DECODE_BYTES 2048
#define PACKETSCOPE_DEFAULT_PAYLOAD_PREVIEW_BYTES 256
#define PACKETSCOPE_DEFAULT_MAX_FLOWS 4096
#define PACKETSCOPE_DEFAULT_STREAM_BUFFER_BYTES 65536
#define PACKETSCOPE_DEFAULT_FLOW_TIMEOUT_SECONDS 60

/*
 * PacketScopeConfig stores runtime options for one PacketScope-C run.
 * Empty interface_name means the capture layer should choose the default device.
 * max_packets of 0 means unlimited capture.
 * Filter values are used only when their matching enabled flag is non-zero.
 * log_path is used only when logging_enabled is non-zero.
 */
typedef struct {
    char interface_name[64];

    bool decode_app;
    bool reassemble;
    size_t payload_decode_bytes;
    size_t payload_preview_bytes;
    size_t max_flows;
    size_t stream_buffer_bytes;
    uint32_t flow_timeout_seconds;

    int max_packets;
    int stats_mode;

    int filter_protocol_enabled;
    Protocol filter_protocol;

    int filter_port_enabled;
    uint16_t filter_port;

    int filter_host_enabled;
    char filter_host[16];

    int filter_payload_text_enabled;
    unsigned char filter_payload_text[PACKETSCOPE_MAX_PAYLOAD_PATTERN_BYTES];
    size_t filter_payload_text_length;

    int filter_payload_hex_enabled;
    unsigned char filter_payload_hex[PACKETSCOPE_MAX_PAYLOAD_PATTERN_BYTES];
    size_t filter_payload_hex_length;

    bool filter_app_enabled;
    AppProtocol filter_app_protocol;

    bool filter_http_host_enabled;
    char filter_http_host[PACKETSCOPE_APP_TEXT_LEN];

    bool filter_http_method_enabled;
    char filter_http_method[16];

    bool filter_dns_query_enabled;
    char filter_dns_query[PACKETSCOPE_APP_TEXT_LEN];

    bool filter_dns_type_enabled;
    uint16_t filter_dns_type;

    bool filter_tls_sni_enabled;
    char filter_tls_sni[PACKETSCOPE_APP_TEXT_LEN];

    bool filter_tls_alpn_enabled;
    char filter_tls_alpn[PACKETSCOPE_TLS_ALPN_LEN];

    int payload_display_enabled;

    int logging_enabled;
    char log_path[256];
} PacketScopeConfig;

typedef PacketScopeConfig AppConfig;

/*
 * Initializes AppConfig with safe default values.
 * Defaults are applied before any future command-line parsing.
 */
void config_init_defaults(AppConfig *config);

#endif
