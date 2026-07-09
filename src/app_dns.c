#include <stdio.h>
#include <string.h>

#include "app_dns.h"
#include "byte_reader.h"

#define DNS_HEADER_LEN 12
#define DNS_POINTER_MASK 0xc0
#define DNS_POINTER_VALUE 0xc0
#define DNS_LABEL_MASK 0x3f
#define DNS_MAX_POINTER_DEPTH 16
#define DNS_MAX_NAME_LEN 253

/*
 * DNS decoding can fail after partially filling fields. Clear on failure so
 * callers never have to reason about stale or half-decoded metadata.
 */
static void clear_app_info(AppInfo *out) {
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
        out->protocol = APP_PROTO_UNKNOWN;
    }
}

/*
 * DNS names may jump through compression pointers. This parser tracks pointer
 * depth and output length so malformed compression cannot loop forever or
 * overrun the caller's fixed metadata buffer.
 */
static int parse_dns_name(const uint8_t *data, size_t length, size_t *offset, char *out,
                          size_t out_size) {
    size_t cursor;
    size_t output_length = 0;
    int jumped = 0;
    int depth = 0;

    if (data == NULL || offset == NULL || out == NULL || out_size == 0 || *offset >= length) {
        return 1;
    }

    cursor = *offset;
    out[0] = '\0';

    while (cursor < length) {
        uint8_t label_len = data[cursor];

        if (label_len == 0) {
            if (!jumped) {
                *offset = cursor + 1;
            }
            if (output_length == 0) {
                if (out_size < 2) {
                    return 1;
                }
                out[0] = '.';
                out[1] = '\0';
            }
            return 0;
        }

        if ((label_len & DNS_POINTER_MASK) == DNS_POINTER_VALUE) {
            uint16_t pointer;

            if (cursor + 1 >= length || depth >= DNS_MAX_POINTER_DEPTH) {
                return 1;
            }
            pointer = (uint16_t)(((uint16_t)(label_len & DNS_LABEL_MASK) << 8) | data[cursor + 1]);
            if (pointer >= length) {
                return 1;
            }
            if (!jumped) {
                *offset = cursor + 2;
            }
            cursor = pointer;
            jumped = 1;
            depth++;
            continue;
        }

        if ((label_len & DNS_POINTER_MASK) != 0 || label_len > 63) {
            return 1;
        }
        cursor++;
        if (cursor + label_len > length) {
            return 1;
        }
        if (output_length != 0) {
            if (output_length + 1 >= out_size || output_length + 1 > DNS_MAX_NAME_LEN) {
                return 1;
            }
            out[output_length] = '.';
            output_length++;
        }
        if (output_length + label_len >= out_size || output_length + label_len > DNS_MAX_NAME_LEN) {
            return 1;
        }
        memcpy(out + output_length, data + cursor, label_len);
        output_length += label_len;
        out[output_length] = '\0';
        cursor += label_len;
    }

    return 1;
}

static int dns_header_is_plausible(uint16_t qdcount, uint16_t ancount, uint16_t nscount,
                                   uint16_t arcount) {
    return qdcount <= 64 && ancount <= 512 && nscount <= 512 && arcount <= 512;
}

/*
 * Decode one DNS message without transport framing. The first question is the
 * only variable-length section parsed for now; answers can be added later on
 * top of the same safe name reader.
 *
 * mDNS (RFC 6762) is wire-compatible with DNS, so app_dns_decode_mdns_message
 * shares this exact parser and only differs in the reported AppProtocol and
 * summary label.
 */
static AppDecodeResult decode_dns_message_as(const uint8_t *data, size_t length, AppInfo *out,
                                             AppProtocol protocol, const char *label) {
    ByteReader reader;
    uint16_t flags;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
    size_t question_offset = DNS_HEADER_LEN;

    clear_app_info(out);
    if (data == NULL || length == 0) {
        return APP_DECODE_NO_MATCH;
    }
    if (length < DNS_HEADER_LEN) {
        return APP_DECODE_NEED_MORE;
    }

    br_init(&reader, data, length);
    out->protocol = protocol;
    if (!br_read_u16_be(&reader, &out->dns_transaction_id) || !br_read_u16_be(&reader, &flags) ||
        !br_read_u16_be(&reader, &out->dns_question_count) || !br_read_u16_be(&reader, &ancount) ||
        !br_read_u16_be(&reader, &nscount) || !br_read_u16_be(&reader, &arcount)) {
        clear_app_info(out);
        return APP_DECODE_NEED_MORE;
    }

    /*
     * Header-only DNS sniffing is noisy against arbitrary payloads, so reject
     * absurd section counts before attempting name parsing.
     */
    if (!dns_header_is_plausible(out->dns_question_count, ancount, nscount, arcount)) {
        clear_app_info(out);
        return APP_DECODE_NO_MATCH;
    }

    out->dns_is_response = (flags & 0x8000) != 0;
    out->dns_opcode = (uint8_t)((flags >> 11) & 0x0f);
    out->dns_rcode = (uint8_t)(flags & 0x0f);

    /*
     * The first question provides the app metadata needed for filtering later:
     * qname, qtype, and qclass.
     */
    if (out->dns_question_count > 0) {
        if (parse_dns_name(data, length, &question_offset, out->dns_query_name,
                           sizeof(out->dns_query_name)) != 0) {
            clear_app_info(out);
            return APP_DECODE_MALFORMED;
        }
        br_init(&reader, data + question_offset, length - question_offset);
        if (!br_read_u16_be(&reader, &out->dns_query_type) ||
            !br_read_u16_be(&reader, &out->dns_query_class)) {
            clear_app_info(out);
            return APP_DECODE_MALFORMED;
        }
    }

    snprintf(out->summary, sizeof(out->summary), "%s %s id=0x%04x q=%u %s", label,
             out->dns_is_response ? "response" : "query", (unsigned int)out->dns_transaction_id,
             (unsigned int)out->dns_question_count, out->dns_query_name);
    return APP_DECODE_OK;
}

AppDecodeResult app_dns_decode_message(const uint8_t *data, size_t length, AppInfo *out) {
    return decode_dns_message_as(data, length, out, APP_PROTO_DNS, "DNS");
}

AppDecodeResult app_dns_decode_mdns_message(const uint8_t *data, size_t length, AppInfo *out) {
    return decode_dns_message_as(data, length, out, APP_PROTO_MDNS, "mDNS");
}

AppDecodeResult app_dns_decode_udp(const uint8_t *data, size_t length, AppInfo *out) {
    /* UDP DNS payloads contain exactly one DNS message without a length prefix. */
    return app_dns_decode_message(data, length, out);
}

AppDecodeResult app_dns_decode_mdns_udp(const uint8_t *data, size_t length, AppInfo *out) {
    /* mDNS over UDP also carries exactly one message without a length prefix. */
    return app_dns_decode_mdns_message(data, length, out);
}

/*
 * DNS over TCP prefixes each message with a two-byte big-endian frame length.
 * Incomplete frames return NEED_MORE for future stream reassembly.
 */
AppDecodeResult app_dns_decode_tcp_frame(const uint8_t *data, size_t length, AppInfo *out) {
    uint16_t frame_length;

    clear_app_info(out);
    if (data == NULL || length == 0) {
        return APP_DECODE_NO_MATCH;
    }
    if (length < 2) {
        return APP_DECODE_NEED_MORE;
    }

    frame_length = (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
    if (frame_length == 0) {
        return APP_DECODE_MALFORMED;
    }
    if (length < 2 + (size_t)frame_length) {
        return APP_DECODE_NEED_MORE;
    }

    return app_dns_decode_message(data + 2, frame_length, out);
}
