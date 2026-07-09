#ifndef APP_DNS_H
#define APP_DNS_H

#include <stddef.h>
#include <stdint.h>

#include "app_decoder.h"
#include "common.h"

/*
 * Decodes one DNS message without a transport framing prefix.
 * Safely handles compressed names with bounds, length, and pointer-depth caps.
 */
AppDecodeResult app_dns_decode_message(const uint8_t *data, size_t length, AppInfo *out);

/*
 * Decodes a DNS message carried directly in one UDP payload.
 */
AppDecodeResult app_dns_decode_udp(const uint8_t *data, size_t length, AppInfo *out);

/*
 * Decodes one DNS-over-TCP frame with its two-byte length prefix.
 * Returns NEED_MORE when the complete frame has not arrived yet.
 */
AppDecodeResult app_dns_decode_tcp_frame(const uint8_t *data, size_t length, AppInfo *out);

#endif
