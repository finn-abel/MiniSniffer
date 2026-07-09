#include <string.h>

#include "bench_common.h"
#include "tcp_reassembly.h"

#define BENCH_ITERATIONS 200000
#define BENCH_STREAM_BUFFER_BYTES 65536
#define BENCH_CHUNK_BYTES 32

int main(void) {
    TcpReassemblyDirection state;
    unsigned char chunk[BENCH_CHUNK_BYTES];
    uint32_t sequence = 1;
    size_t i;
    double start;
    double elapsed;
    volatile int sink = 0;

    memset(chunk, 'A', sizeof(chunk));
    if (!tcp_reassembly_direction_init(&state, BENCH_STREAM_BUFFER_BYTES)) {
        return 1;
    }

    start = bench_now_seconds();
    for (i = 0; i < BENCH_ITERATIONS; i++) {
        /*
         * Once a direction's fixed buffer fills, further appends are simply
         * dropped rather than growing memory. Reinitialize periodically so
         * the benchmark keeps exercising the in-order append path instead of
         * measuring an already-full, always-dropping buffer.
         */
        if ((size_t)(BENCH_CHUNK_BYTES) > BENCH_STREAM_BUFFER_BYTES - state.stream.length) {
            tcp_reassembly_direction_cleanup(&state);
            if (!tcp_reassembly_direction_init(&state, BENCH_STREAM_BUFFER_BYTES)) {
                return 1;
            }
            sequence = 1;
        }

        sink += (int)tcp_reassembly_process_segment(&state, sequence, 0, chunk, sizeof(chunk));
        sequence += BENCH_CHUNK_BYTES;
    }
    elapsed = bench_now_seconds() - start;

    bench_report("tcp_reassembly_process_segment", BENCH_ITERATIONS, elapsed);
    tcp_reassembly_direction_cleanup(&state);
    (void)sink;
    return 0;
}
