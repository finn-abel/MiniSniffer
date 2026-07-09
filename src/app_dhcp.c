#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "app_dhcp.h"
#include "byte_reader.h"

#define BOOTP_FIXED_HEADER_LEN 236
#define DHCP_MAGIC_COOKIE_LEN 4
#define DHCP_MIN_MESSAGE_LEN (BOOTP_FIXED_HEADER_LEN + DHCP_MAGIC_COOKIE_LEN)
#define BOOTP_CIADDR_OFFSET 12
#define BOOTP_YIADDR_OFFSET 16
#define BOOTP_SIADDR_OFFSET 20
#define BOOTP_CHADDR_OFFSET 28
#define BOOTP_HTYPE_ETHERNET 1
#define BOOTP_HLEN_ETHERNET 6
#define BOOTP_OP_REQUEST 1
#define BOOTP_OP_REPLY 2
#define DHCP_OPTION_PAD 0
#define DHCP_OPTION_END 255
#define DHCP_OPTION_REQUESTED_IP 50
#define DHCP_OPTION_MESSAGE_TYPE 53

static const unsigned char DHCP_MAGIC_COOKIE[DHCP_MAGIC_COOKIE_LEN] = {0x63, 0x82, 0x53, 0x63};

/*
 * DHCP decoding can fail after partially filling fields. Clear on failure so
 * callers never have to reason about stale or half-decoded metadata.
 */
static void clear_app_info(AppInfo *out) {
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
        out->protocol = APP_PROTO_UNKNOWN;
    }
}

static const char *dhcp_message_type_name(uint8_t type) {
    switch (type) {
    case 1:
        return "discover";
    case 2:
        return "offer";
    case 3:
        return "request";
    case 4:
        return "decline";
    case 5:
        return "ack";
    case 6:
        return "nak";
    case 7:
        return "release";
    case 8:
        return "inform";
    default:
        return "unknown";
    }
}

/*
 * DHCP options are a TLV sequence after the four-byte magic cookie. Only the
 * message type (53) and requested IP (50) options are extracted; unknown
 * options are safely skipped using their own length byte. A truncated or
 * missing length/value at the tail simply stops the scan rather than failing
 * the whole decode, since the fixed header and cookie already confirmed this
 * is a DHCP message.
 */
static void scan_dhcp_options(const uint8_t *data, size_t length, AppInfo *out) {
    size_t offset = DHCP_MIN_MESSAGE_LEN;

    while (offset < length) {
        uint8_t tag = data[offset];
        uint8_t option_length;
        const uint8_t *value;

        if (tag == DHCP_OPTION_END) {
            return;
        }
        if (tag == DHCP_OPTION_PAD) {
            offset++;
            continue;
        }
        if (offset + 1 >= length) {
            return;
        }
        option_length = data[offset + 1];
        if (offset + 2 + (size_t)option_length > length) {
            return;
        }
        value = data + offset + 2;

        if (tag == DHCP_OPTION_MESSAGE_TYPE && option_length == 1) {
            out->dhcp_message_type = value[0];
        } else if (tag == DHCP_OPTION_REQUESTED_IP && option_length == 4) {
            inet_ntop(AF_INET, value, out->dhcp_requested_ip, sizeof(out->dhcp_requested_ip));
        }
        offset += 2 + (size_t)option_length;
    }
}

/*
 * DHCP is decoded only via its BOOTP fixed header plus magic cookie. This is a
 * strong, well-bounded signature, so DHCP is dispatched by port (67/68) rather
 * than sniffed blindly like HTTP or TLS.
 */
AppDecodeResult app_dhcp_decode_udp(const uint8_t *data, size_t length, AppInfo *out) {
    ByteReader reader;
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;

    clear_app_info(out);
    if (data == NULL || length == 0) {
        return APP_DECODE_NO_MATCH;
    }
    if (length < DHCP_MIN_MESSAGE_LEN) {
        return APP_DECODE_NEED_MORE;
    }
    if (memcmp(data + BOOTP_FIXED_HEADER_LEN, DHCP_MAGIC_COOKIE, DHCP_MAGIC_COOKIE_LEN) != 0) {
        return APP_DECODE_NO_MATCH;
    }

    br_init(&reader, data, length);
    if (!br_read_u8(&reader, &op) || !br_read_u8(&reader, &htype) || !br_read_u8(&reader, &hlen) ||
        !br_skip(&reader, 1) || !br_read_u32_be(&reader, &out->dhcp_transaction_id)) {
        clear_app_info(out);
        return APP_DECODE_NEED_MORE;
    }
    if (op != BOOTP_OP_REQUEST && op != BOOTP_OP_REPLY) {
        clear_app_info(out);
        return APP_DECODE_NO_MATCH;
    }

    out->protocol = APP_PROTO_DHCP;
    inet_ntop(AF_INET, data + BOOTP_CIADDR_OFFSET, out->dhcp_client_ip,
             sizeof(out->dhcp_client_ip));
    inet_ntop(AF_INET, data + BOOTP_YIADDR_OFFSET, out->dhcp_your_ip, sizeof(out->dhcp_your_ip));
    inet_ntop(AF_INET, data + BOOTP_SIADDR_OFFSET, out->dhcp_server_ip,
             sizeof(out->dhcp_server_ip));
    if (htype == BOOTP_HTYPE_ETHERNET && hlen == BOOTP_HLEN_ETHERNET) {
        snprintf(out->dhcp_client_mac, sizeof(out->dhcp_client_mac),
                 "%02x:%02x:%02x:%02x:%02x:%02x", data[BOOTP_CHADDR_OFFSET],
                 data[BOOTP_CHADDR_OFFSET + 1], data[BOOTP_CHADDR_OFFSET + 2],
                 data[BOOTP_CHADDR_OFFSET + 3], data[BOOTP_CHADDR_OFFSET + 4],
                 data[BOOTP_CHADDR_OFFSET + 5]);
    }

    scan_dhcp_options(data, length, out);

    snprintf(out->summary, sizeof(out->summary), "DHCP %s xid=0x%08x",
             dhcp_message_type_name(out->dhcp_message_type),
             (unsigned int)out->dhcp_transaction_id);
    return APP_DECODE_OK;
}
