#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#include "common.h"

#define MINISNIFFER_MAX_PAYLOAD_PATTERN_BYTES 128
#define MINISNIFFER_DEFAULT_PAYLOAD_DECODE_BYTES 2048
#define MINISNIFFER_MAX_PAYLOAD_DECODE_BYTES 65535
#define MINISNIFFER_DEFAULT_PAYLOAD_PREVIEW_BYTES 256
#define MINISNIFFER_DEFAULT_MAX_FLOWS 512
#define MINISNIFFER_DEFAULT_STREAM_BUFFER_BYTES 32768
#define MINISNIFFER_DEFAULT_FLOW_TIMEOUT_SECONDS 60
#define MINISNIFFER_MAX_FLOWS 1024
#define MINISNIFFER_MAX_STREAM_BUFFER_BYTES 1048576
#define MINISNIFFER_MAX_TOTAL_REASSEMBLY_BYTES 134217728
#define MINISNIFFER_DEFAULT_IPV4_FRAGMENT_MAX_DATAGRAMS 64
#define MINISNIFFER_DEFAULT_IPV4_FRAGMENT_MAX_BYTES 1048576
#define MINISNIFFER_DEFAULT_IPV4_FRAGMENT_TIMEOUT_SECONDS 30
#define MINISNIFFER_MAX_IPV4_FRAGMENT_DATAGRAMS 1024
#define MINISNIFFER_MAX_IPV4_FRAGMENT_BYTES 16777216
#define MINISNIFFER_VERSION "0.2.0"

typedef enum { LOG_FLUSH_ALWAYS = 0, LOG_FLUSH_LINE, LOG_FLUSH_EXIT } LogFlushMode;
typedef enum {
    DOMAIN_MATCH_NORMALIZED = 0,
    DOMAIN_MATCH_EXACT,
    DOMAIN_MATCH_IDNA
} DomainMatchMode;

/*
 * MiniSnifferConfig stores runtime options for one MiniSniffer-C run.
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
    size_t ipv4_fragment_max_datagrams;
    size_t ipv4_fragment_max_bytes;
    uint32_t ipv4_fragment_timeout_seconds;

    int max_packets;
    int stats_mode;
    bool version_requested;
    bool list_interfaces;
    bool quiet;
    bool verbose;
    bool color_enabled;
    bool json_output;
    LogFlushMode log_flush_mode;
    bool read_path_enabled;
    char read_path[256];
    bool write_path_enabled;
    char write_path[256];
    bool no_bpf;

    int filter_protocol_enabled;
    Protocol filter_protocol;

    int filter_port_enabled;
    uint16_t filter_port;

    int filter_host_enabled;
    char filter_host[MINISNIFFER_IP_TEXT_LEN];

    int filter_payload_text_enabled;
    unsigned char filter_payload_text[MINISNIFFER_MAX_PAYLOAD_PATTERN_BYTES];
    size_t filter_payload_text_length;

    int filter_payload_hex_enabled;
    unsigned char filter_payload_hex[MINISNIFFER_MAX_PAYLOAD_PATTERN_BYTES];
    size_t filter_payload_hex_length;

    bool filter_app_enabled;
    AppProtocol filter_app_protocol;

    bool filter_http_host_enabled;
    char filter_http_host[MINISNIFFER_APP_TEXT_LEN];

    bool filter_http_method_enabled;
    char filter_http_method[16];

    bool filter_dns_query_enabled;
    char filter_dns_query[MINISNIFFER_APP_TEXT_LEN];

    bool filter_dns_type_enabled;
    uint16_t filter_dns_type;

    bool filter_tls_sni_enabled;
    char filter_tls_sni[MINISNIFFER_APP_TEXT_LEN];

    bool filter_tls_alpn_enabled;
    char filter_tls_alpn[MINISNIFFER_TLS_ALPN_LEN];
    DomainMatchMode domain_match_mode;

    bool filter_dhcp_type_enabled;
    uint8_t filter_dhcp_type;

    bool filter_quic_version_enabled;
    uint32_t filter_quic_version;

    int payload_display_enabled;

    int logging_enabled;
    char log_path[256];
} MiniSnifferConfig;

typedef MiniSnifferConfig AppConfig;

/*
 * Initializes AppConfig with safe default values.
 * Defaults are applied before any future command-line parsing.
 */
void config_init_defaults(AppConfig *config);

#endif
