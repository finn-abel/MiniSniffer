#ifndef APP_DHCP_H
#define APP_DHCP_H

#include <stddef.h>
#include <stdint.h>

#include "app_decoder.h"
#include "common.h"

/*
 * Decodes DHCP metadata carried directly in one UDP payload (client port 68 or
 * server port 67). Requires the DHCP magic cookie after the fixed BOOTP header
 * so unrelated UDP broadcast traffic on those ports is not misclassified.
 */
AppDecodeResult app_dhcp_decode_udp(const uint8_t *data, size_t length, AppInfo *out);

#endif
