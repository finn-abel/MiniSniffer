#include <pcap/pcap.h>

#include "fuzz_common.h"
#include "parser.h"

/*
 * The first fuzz byte selects a supported libpcap datalink type so one
 * corpus can exercise every link-layer decoder parser.c supports; the rest
 * of the input is the raw link-layer frame.
 */
static int pick_datalink(uint8_t selector) {
    switch (selector % 4) {
    case 0:
        return DLT_EN10MB;
    case 1:
        return DLT_RAW;
    case 2:
        return DLT_NULL;
    default:
#ifdef DLT_LINUX_SLL
        return DLT_LINUX_SLL;
#else
        return DLT_EN10MB;
#endif
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    PacketInfo info;

    if (size < 1) {
        return 0;
    }

    (void)parser_parse_packet_with_datalink(data + 1, size - 1, pick_datalink(data[0]), &info);
    return 0;
}
