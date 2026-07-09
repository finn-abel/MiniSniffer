#ifndef COMMON_H
#define COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MINISNIFFER_IP_TEXT_LEN 46
#define MINISNIFFER_MAX_PAYLOAD_PREVIEW_BYTES 256
#define MINISNIFFER_APP_TEXT_LEN 256
#define MINISNIFFER_MAX_IPV4_HEADER_BYTES 60
#define MINISNIFFER_MAC_TEXT_LEN 18
#define MINISNIFFER_QUIC_CID_MAX_BYTES 20
#define MINISNIFFER_QUIC_CID_TEXT_LEN 41

/*
 * Protocol describes the coarse protocol category for a packet.
 * Parsers assign this value after inspecting packet headers.
 * Filters, logs, and stats use it for consistent behavior.
 * ARP has no transport ports; src_ip/dst_ip hold the sender/target IPv4
 * addresses so host filters keep working without special-casing ARP.
 */
typedef enum { PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_ARP, PROTO_OTHER } Protocol;

/*
 * AppProtocol describes decoded application-layer metadata. UNKNOWN means no
 * app decoder matched or decoding has not been requested. MDNS reuses the DNS
 * message parser and AppInfo fields since mDNS is wire-compatible with DNS.
 */
typedef enum {
    APP_PROTO_UNKNOWN = 0,
    APP_PROTO_HTTP,
    APP_PROTO_DNS,
    APP_PROTO_TLS,
    APP_PROTO_DHCP,
    APP_PROTO_MDNS,
    APP_PROTO_QUIC
} AppProtocol;

typedef enum {
    APP_DECODE_STATUS_NOT_RUN = 0,
    APP_DECODE_STATUS_NO_MATCH,
    APP_DECODE_STATUS_NEED_MORE,
    APP_DECODE_STATUS_MALFORMED,
    APP_DECODE_STATUS_TRUNCATED,
    APP_DECODE_STATUS_DECODED
} AppDecodeStatus;

#define MINISNIFFER_APP_SUMMARY_LEN 128
#define MINISNIFFER_TLS_ALPN_LEN 256

/*
 * AppInfo is shared by packet-local app decoding now and flow-level app
 * decoding later. Protocol-specific metadata fields will be added as decoders
 * are filled in.
 */
typedef struct {
    AppProtocol protocol;
    char summary[MINISNIFFER_APP_SUMMARY_LEN];

    char http_method[16];
    char http_path[MINISNIFFER_APP_TEXT_LEN];
    char http_version[16];
    char http_host[MINISNIFFER_APP_TEXT_LEN];
    char http_user_agent[MINISNIFFER_APP_TEXT_LEN];
    uint16_t http_status_code;
    char http_reason[MINISNIFFER_APP_TEXT_LEN];
    char http_content_type[MINISNIFFER_APP_TEXT_LEN];

    uint16_t dns_transaction_id;
    int dns_is_response;
    uint8_t dns_opcode;
    uint8_t dns_rcode;
    uint16_t dns_question_count;
    char dns_query_name[MINISNIFFER_APP_TEXT_LEN];
    uint16_t dns_query_type;
    uint16_t dns_query_class;

    uint16_t tls_record_version;
    uint8_t tls_handshake_type;
    uint16_t tls_client_version;
    char tls_sni[MINISNIFFER_APP_TEXT_LEN];
    char tls_alpn[MINISNIFFER_TLS_ALPN_LEN];

    uint8_t dhcp_message_type;
    uint32_t dhcp_transaction_id;
    char dhcp_client_mac[MINISNIFFER_MAC_TEXT_LEN];
    char dhcp_client_ip[MINISNIFFER_IP_TEXT_LEN];
    char dhcp_your_ip[MINISNIFFER_IP_TEXT_LEN];
    char dhcp_server_ip[MINISNIFFER_IP_TEXT_LEN];
    char dhcp_requested_ip[MINISNIFFER_IP_TEXT_LEN];

    uint32_t quic_version;
    char quic_dcid[MINISNIFFER_QUIC_CID_TEXT_LEN];
    char quic_scid[MINISNIFFER_QUIC_CID_TEXT_LEN];
} AppInfo;

/*
 * PacketInfo represents one captured packet after basic parsing.
 * It stores source and destination IP address text, optional transport ports,
 * protocol type, packet number, packet size, a direct payload view, and a
 * bounded payload preview.
 * has_ports is non-zero only when src_port and dst_port are valid.
 */
typedef struct {
    char src_ip[MINISNIFFER_IP_TEXT_LEN];
    char dst_ip[MINISNIFFER_IP_TEXT_LEN];

    uint16_t src_port;
    uint16_t dst_port;

    Protocol protocol;
    int ip_version;

    uint32_t packet_number;
    size_t size;
    char timestamp[32];

    int has_ports;

    int has_tcp_sequence;
    uint32_t tcp_sequence;
    uint8_t tcp_flags;

    int has_icmp;
    uint8_t icmp_type;
    uint8_t icmp_code;

    int is_ipv4_fragment;
    uint16_t ipv4_identification;
    uint8_t ipv4_protocol_number;
    size_t ipv4_header_length;
    size_t ipv4_fragment_offset;
    int ipv4_more_fragments;
    size_t ipv4_fragment_payload_length;
    const uint8_t *ipv4_fragment_payload;
    unsigned char ipv4_header[MINISNIFFER_MAX_IPV4_HEADER_BYTES];

    /*
     * ARP has no transport ports or IP header. Sender/target IPv4 addresses
     * are stored in src_ip/dst_ip above so protocol/host filters and CSV/JSON
     * address fields work without special-casing ARP.
     */
    int has_arp;
    uint16_t arp_operation;
    char arp_sender_mac[MINISNIFFER_MAC_TEXT_LEN];
    char arp_target_mac[MINISNIFFER_MAC_TEXT_LEN];

    int has_payload;
    const uint8_t *payload;
    size_t payload_capture_length;
    size_t payload_decode_length;
    size_t payload_preview_length;
    unsigned char payload_preview[MINISNIFFER_MAX_PAYLOAD_PREVIEW_BYTES];

    AppDecodeStatus app_decode_status;
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
    uint32_t arp_packets;
    uint32_t other_packets;

    size_t total_bytes;

    /*
     * raw_packets_seen counts every packet libpcap delivered, regardless of
     * filtering or parse outcome. packets_filtered_out counts packets that
     * were parsed successfully but did not pass the active filters, so were
     * never displayed. parse_failures counts packets the parser could not
     * summarize at all; these are skipped rather than aborting capture.
     */
    uint32_t raw_packets_seen;
    uint32_t packets_filtered_out;
    uint32_t parse_failures;

    uint32_t ipv4_fragments_seen;
    uint32_t ipv4_fragments_reassembled;
    uint32_t ipv4_fragments_expired;
    uint32_t ipv4_fragments_malformed;
    uint32_t ipv4_fragments_dropped;
    size_t ipv4_fragment_bytes_in_use;
    size_t ipv4_fragment_bytes_configured_max;

    /*
     * pcap_stats_available is false for offline reads and on platforms where
     * libpcap's driver-level counters are not supported; the three counters
     * below are only meaningful when it is true.
     */
    bool pcap_stats_available;
    uint32_t pcap_packets_received;
    uint32_t pcap_packets_dropped;
    uint32_t pcap_packets_if_dropped;

    uint32_t app_decode_no_match;
    uint32_t app_decode_need_more;
    uint32_t app_decode_malformed;
    uint32_t app_decode_truncated;
    uint32_t app_decode_decoded;

    uint64_t flow_count_created;
    uint64_t flow_count_active_at_exit;
    uint64_t flow_closed_fin;
    uint64_t flow_closed_rst;
    uint64_t flow_evicted_idle;
    uint64_t flow_evicted_capacity;
    uint64_t flow_retransmissions;
    uint64_t flow_out_of_order_segments;
    uint64_t flow_overlapping_segments;
    uint64_t flow_gaps;
    size_t flow_stream_bytes_in_use;
    size_t flow_stream_bytes_configured_max;
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

const char *app_decode_status_to_string(AppDecodeStatus status);

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
