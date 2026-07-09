#include "app_dns.h"
#include "fuzz_common.h"

/*
 * The first fuzz byte selects which DNS entry point to exercise: raw
 * message, length-prefixed TCP framing, or the mDNS variant that reuses the
 * same wire-format parser under a different AppProtocol tag.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    AppInfo info;

    if (size < 1) {
        return 0;
    }

    switch (data[0] % 3) {
    case 0:
        app_dns_decode_message(data + 1, size - 1, &info);
        break;
    case 1:
        app_dns_decode_tcp_frame(data + 1, size - 1, &info);
        break;
    default:
        app_dns_decode_mdns_message(data + 1, size - 1, &info);
        break;
    }

    return 0;
}
