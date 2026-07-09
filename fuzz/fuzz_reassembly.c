#include <string.h>

#include "fuzz_common.h"
#include "tcp_reassembly.h"

#define FUZZ_REASSEMBLY_BUFFER_BYTES 4096
#define FUZZ_REASSEMBLY_MAX_CHUNK 256
#define FUZZ_REASSEMBLY_RECORD_HEADER_LEN 7

/*
 * Feeds a whole sequence of TCP segments (not just one call) into a single
 * reassembly direction, since the interesting bugs in reassembly are
 * stateful across gaps, overlaps, and retransmissions rather than visible
 * from any single segment. Each record in the input is
 * [flags(1)][sequence(4)][length hint(2)][chunk bytes...]; length hints
 * are clamped to a bounded chunk size and to the bytes actually available.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TcpReassemblyDirection state;
    size_t offset = 0;

    if (!tcp_reassembly_direction_init(&state, FUZZ_REASSEMBLY_BUFFER_BYTES)) {
        return 0;
    }

    while (offset + FUZZ_REASSEMBLY_RECORD_HEADER_LEN <= size) {
        uint8_t flags = data[offset];
        uint32_t sequence;
        uint16_t chunk_length;
        size_t available;

        memcpy(&sequence, data + offset + 1, sizeof(sequence));
        memcpy(&chunk_length, data + offset + 5, sizeof(chunk_length));
        offset += FUZZ_REASSEMBLY_RECORD_HEADER_LEN;

        available = size - offset;
        if (chunk_length > FUZZ_REASSEMBLY_MAX_CHUNK) {
            chunk_length = (uint16_t)(chunk_length % (FUZZ_REASSEMBLY_MAX_CHUNK + 1));
        }
        if (chunk_length > available) {
            chunk_length = (uint16_t)available;
        }

        (void)tcp_reassembly_process_segment(&state, sequence, flags, data + offset, chunk_length);
        offset += chunk_length;
    }

    tcp_reassembly_direction_cleanup(&state);
    return 0;
}
