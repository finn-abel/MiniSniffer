#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_dhcp.h"

#define DHCP_MESSAGE_BUFFER_LEN 300
#define BOOTP_FIXED_HEADER_LEN 236

static size_t build_dhcp_message(uint8_t *buffer, size_t buffer_size, uint8_t op, uint8_t htype,
                                 uint8_t hlen, uint32_t xid, const uint8_t *chaddr,
                                 const uint8_t *options, size_t options_len) {
    assert(buffer_size >= BOOTP_FIXED_HEADER_LEN + 4 + options_len);
    memset(buffer, 0, buffer_size);

    buffer[0] = op;
    buffer[1] = htype;
    buffer[2] = hlen;
    buffer[3] = 0;
    buffer[4] = (uint8_t)(xid >> 24);
    buffer[5] = (uint8_t)(xid >> 16);
    buffer[6] = (uint8_t)(xid >> 8);
    buffer[7] = (uint8_t)xid;
    if (chaddr != NULL && hlen <= 16) {
        memcpy(buffer + 28, chaddr, hlen);
    }
    buffer[BOOTP_FIXED_HEADER_LEN] = 0x63;
    buffer[BOOTP_FIXED_HEADER_LEN + 1] = 0x82;
    buffer[BOOTP_FIXED_HEADER_LEN + 2] = 0x53;
    buffer[BOOTP_FIXED_HEADER_LEN + 3] = 0x63;
    if (options_len > 0) {
        memcpy(buffer + BOOTP_FIXED_HEADER_LEN + 4, options, options_len);
    }

    return BOOTP_FIXED_HEADER_LEN + 4 + options_len;
}

static void test_app_dhcp_decode_discover(void) {
    static const uint8_t chaddr[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t options[] = {53, 1, 1, 255};
    uint8_t buffer[DHCP_MESSAGE_BUFFER_LEN];
    size_t length;
    AppInfo info;

    length = build_dhcp_message(buffer, sizeof(buffer), 1, 1, 6, 0x12345678, chaddr, options,
                                sizeof(options));

    assert(app_dhcp_decode_udp(buffer, length, &info) == APP_DECODE_OK);
    assert(info.protocol == APP_PROTO_DHCP);
    assert(info.dhcp_message_type == 1);
    assert(info.dhcp_transaction_id == 0x12345678);
    assert(strcmp(info.dhcp_client_mac, "00:11:22:33:44:55") == 0);
    assert(info.dhcp_requested_ip[0] == '\0');
}

static void test_app_dhcp_decode_request_with_requested_ip(void) {
    static const uint8_t options[] = {53, 1, 3, 50, 4, 192, 168, 1, 50, 255};
    uint8_t buffer[DHCP_MESSAGE_BUFFER_LEN];
    size_t length;
    AppInfo info;

    length = build_dhcp_message(buffer, sizeof(buffer), 1, 1, 6, 1, NULL, options, sizeof(options));

    assert(app_dhcp_decode_udp(buffer, length, &info) == APP_DECODE_OK);
    assert(info.dhcp_message_type == 3);
    assert(strcmp(info.dhcp_requested_ip, "192.168.1.50") == 0);
}

static void test_app_dhcp_decode_ack_reports_offered_addresses(void) {
    static const uint8_t options[] = {53, 1, 5, 255};
    uint8_t buffer[DHCP_MESSAGE_BUFFER_LEN];
    size_t length;
    AppInfo info;

    length = build_dhcp_message(buffer, sizeof(buffer), 2, 1, 6, 1, NULL, options, sizeof(options));
    buffer[16] = 192;
    buffer[17] = 168;
    buffer[18] = 1;
    buffer[19] = 77;
    buffer[20] = 192;
    buffer[21] = 168;
    buffer[22] = 1;
    buffer[23] = 1;

    assert(app_dhcp_decode_udp(buffer, length, &info) == APP_DECODE_OK);
    assert(info.dhcp_message_type == 5);
    assert(strcmp(info.dhcp_your_ip, "192.168.1.77") == 0);
    assert(strcmp(info.dhcp_server_ip, "192.168.1.1") == 0);
}

static void test_app_dhcp_ignores_unknown_options_and_padding(void) {
    static const uint8_t options[] = {0, 0, 12, 3, 'p', 'c', '1', 53, 1, 1, 0, 255};
    uint8_t buffer[DHCP_MESSAGE_BUFFER_LEN];
    size_t length;
    AppInfo info;

    length = build_dhcp_message(buffer, sizeof(buffer), 1, 1, 6, 1, NULL, options, sizeof(options));

    assert(app_dhcp_decode_udp(buffer, length, &info) == APP_DECODE_OK);
    assert(info.dhcp_message_type == 1);
}

static void test_app_dhcp_stops_scan_on_truncated_trailing_option(void) {
    static const uint8_t options[] = {53, 1, 1, 12, 5};
    uint8_t buffer[DHCP_MESSAGE_BUFFER_LEN];
    size_t length;
    AppInfo info;

    length = build_dhcp_message(buffer, sizeof(buffer), 1, 1, 6, 1, NULL, options, sizeof(options));

    assert(app_dhcp_decode_udp(buffer, length, &info) == APP_DECODE_OK);
    assert(info.dhcp_message_type == 1);
}

static void test_app_dhcp_rejects_missing_magic_cookie(void) {
    uint8_t buffer[DHCP_MESSAGE_BUFFER_LEN];
    AppInfo info;

    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 1;

    assert(app_dhcp_decode_udp(buffer, BOOTP_FIXED_HEADER_LEN + 4, &info) == APP_DECODE_NO_MATCH);
    assert(info.protocol == APP_PROTO_UNKNOWN);
}

static void test_app_dhcp_rejects_invalid_op(void) {
    static const uint8_t options[] = {255};
    uint8_t buffer[DHCP_MESSAGE_BUFFER_LEN];
    size_t length;
    AppInfo info;

    length = build_dhcp_message(buffer, sizeof(buffer), 9, 1, 6, 1, NULL, options, sizeof(options));

    assert(app_dhcp_decode_udp(buffer, length, &info) == APP_DECODE_NO_MATCH);
    assert(info.protocol == APP_PROTO_UNKNOWN);
}

static void test_app_dhcp_reports_need_more_for_short_buffers(void) {
    uint8_t buffer[BOOTP_FIXED_HEADER_LEN];
    AppInfo info;

    memset(buffer, 0, sizeof(buffer));
    assert(app_dhcp_decode_udp(buffer, sizeof(buffer), &info) == APP_DECODE_NEED_MORE);
    assert(info.protocol == APP_PROTO_UNKNOWN);
}

static void test_app_dhcp_rejects_null_and_empty_input(void) {
    AppInfo info;

    assert(app_dhcp_decode_udp(NULL, 0, &info) == APP_DECODE_NO_MATCH);
    assert(info.protocol == APP_PROTO_UNKNOWN);
    assert(app_dhcp_decode_udp((const uint8_t *)"", 0, &info) == APP_DECODE_NO_MATCH);
}

static void test_app_dhcp_skips_client_mac_for_non_ethernet_hardware(void) {
    static const uint8_t options[] = {53, 1, 1, 255};
    uint8_t buffer[DHCP_MESSAGE_BUFFER_LEN];
    size_t length;
    AppInfo info;

    length = build_dhcp_message(buffer, sizeof(buffer), 1, 6, 8, 1, NULL, options, sizeof(options));

    assert(app_dhcp_decode_udp(buffer, length, &info) == APP_DECODE_OK);
    assert(info.dhcp_client_mac[0] == '\0');
}

int main(void) {
    test_app_dhcp_decode_discover();
    test_app_dhcp_decode_request_with_requested_ip();
    test_app_dhcp_decode_ack_reports_offered_addresses();
    test_app_dhcp_ignores_unknown_options_and_padding();
    test_app_dhcp_stops_scan_on_truncated_trailing_option();
    test_app_dhcp_rejects_missing_magic_cookie();
    test_app_dhcp_rejects_invalid_op();
    test_app_dhcp_reports_need_more_for_short_buffers();
    test_app_dhcp_rejects_null_and_empty_input();
    test_app_dhcp_skips_client_mac_for_non_ethernet_hardware();

    printf("All app DHCP tests passed.\n");

    return 0;
}
