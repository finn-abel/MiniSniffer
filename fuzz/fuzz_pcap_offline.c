#include <pcap/pcap.h>
#include <stdio.h>

#include "fuzz_common.h"
#include "parser.h"

#define FUZZ_PCAP_OFFLINE_MAX_PACKETS 10000

/*
 * Treats the raw fuzz input as an entire .pcap file and drives it through
 * the same offline-read path capture.c uses for --read: pcap_fopen_offline
 * plus a pcap_next_ex loop feeding parser_parse_packet_with_datalink. This
 * exercises libpcap's own savefile parsing against arbitrary/corrupted
 * bytes in addition to MiniSniffer's parser, without ever touching a live
 * interface or requiring elevated permissions.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    FILE *memory_file;
    pcap_t *handle;
    int datalink_type;

    if (size == 0) {
        return 0;
    }

    memory_file = fmemopen((void *)data, size, "rb");
    if (memory_file == NULL) {
        return 0;
    }

    /* On success, pcap_close() below takes ownership of memory_file. */
    handle = pcap_fopen_offline(memory_file, error_buffer);
    if (handle == NULL) {
        fclose(memory_file);
        return 0;
    }

    datalink_type = pcap_datalink(handle);
    if (parser_supports_datalink(datalink_type)) {
        struct pcap_pkthdr *header = NULL;
        const unsigned char *packet = NULL;
        int guard;

        /*
         * Bound total packets processed per fuzz iteration so a crafted
         * file claiming an enormous packet count cannot make one input run
         * unboundedly long; libFuzzer already bounds input size separately.
         */
        for (guard = 0; guard < FUZZ_PCAP_OFFLINE_MAX_PACKETS; guard++) {
            PacketInfo info;
            int result = pcap_next_ex(handle, &header, &packet);

            if (result != 1) {
                break;
            }
            (void)parser_parse_packet_with_datalink(packet, header->caplen, datalink_type, &info);
        }
    }

    pcap_close(handle);
    return 0;
}
