#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>

#define PACKETSCOPE_MAX_PAYLOAD_PREVIEW_BYTES 256
#define PACKETSCOPE_APP_TEXT_LEN 256

/*
 * Protocol describes the coarse protocol category for a packet.
 * Parsers assign this value after inspecting packet headers.
 * Filters, logs, and stats use it for consistent behavior.
 */
typedef enum {
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_OTHER
} Protocol;

/*
 * AppProtocol describes decoded application-layer metadata. UNKNOWN means no
 * app decoder matched or decoding has not been requested.
 */
typedef enum {
    APP_PROTO_UNKNOWN = 0,
    APP_PROTO_HTTP,
    APP_PROTO_DNS,
    APP_PROTO_TLS
} AppProtocol;

#define PACKETSCOPE_APP_SUMMARY_LEN 128
#define PACKETSCOPE_TLS_ALPN_LEN 256

/*
 * AppInfo is shared by packet-local app decoding now and flow-level app
 * decoding later. Protocol-specific metadata fields will be added as decoders
 * are filled in.
 */
typedef struct {
    AppProtocol protocol;
    char summary[PACKETSCOPE_APP_SUMMARY_LEN];

    char http_method[16];
    char http_path[PACKETSCOPE_APP_TEXT_LEN];
    char http_version[16];
    char http_host[PACKETSCOPE_APP_TEXT_LEN];
    char http_user_agent[PACKETSCOPE_APP_TEXT_LEN];
    uint16_t http_status_code;
    char http_reason[PACKETSCOPE_APP_TEXT_LEN];
    char http_content_type[PACKETSCOPE_APP_TEXT_LEN];

    uint16_t dns_transaction_id;
    int dns_is_response;
    uint8_t dns_opcode;
    uint8_t dns_rcode;
    uint16_t dns_question_count;
    char dns_query_name[PACKETSCOPE_APP_TEXT_LEN];
    uint16_t dns_query_type;
    uint16_t dns_query_class;

    uint16_t tls_record_version;
    uint8_t tls_handshake_type;
    uint16_t tls_client_version;
    char tls_sni[PACKETSCOPE_APP_TEXT_LEN];
    char tls_alpn[PACKETSCOPE_TLS_ALPN_LEN];
} AppInfo;

/*
 * PacketInfo represents one captured packet after basic parsing.
 * It stores source and destination IPv4 addresses, optional transport ports,
 * protocol type, packet number, packet size, a direct payload view, and a
 * bounded payload preview.
 * has_ports is non-zero only when src_port and dst_port are valid.
 */
typedef struct {
    char src_ip[16];
    char dst_ip[16];

    uint16_t src_port;
    uint16_t dst_port;

    Protocol protocol;

    uint32_t packet_number;
    size_t size;
    char timestamp[32];

    int has_ports;

    int has_tcp_sequence;
    uint32_t tcp_sequence;
    uint8_t tcp_flags;

    int has_payload;
    const uint8_t *payload;
    size_t payload_capture_length;
    size_t payload_decode_length;
    size_t payload_preview_length;
    unsigned char payload_preview[PACKETSCOPE_MAX_PAYLOAD_PREVIEW_BYTES];

    AppInfo app;
} PacketInfo;

/*
 * PacketStats stores running traffic counters.
 * It tracks the total packet count, per-protocol counts, and total bytes.
 * Stats mode and summary output will read from this struct.
 */
typedef struct {
    uint32_t total_packets;
    uint32_t tcp_packets;
    uint32_t udp_packets;
    uint32_t icmp_packets;
    uint32_t other_packets;

    size_t total_bytes;
} PacketStats;

/*
 * Converts a Protocol value into a stable display string.
 * Unknown or fallback protocol values are displayed as OTHER.
 */
const char *protocol_to_string(Protocol protocol);

/*
 * Parses a protocol name into a Protocol value.
 * Returns 0 for tcp, udp, icmp, or other.
 * Returns non-zero when text does not name a supported protocol.
 */
int protocol_from_string(const char *text, Protocol *protocol);

/*
 * Prints one readable packet summary line.
 * The line includes packet number, protocol, addresses when available, and size.
 */
void packet_info_print(const PacketInfo *info);

/*
 * Prints a bounded payload preview in hex and printable ASCII.
 * preview_limit caps how many bytes from PacketInfo's payload preview are shown.
 */
void packet_info_print_payload(const PacketInfo *info, size_t preview_limit);

#endif
