#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H

#include <stddef.h>
#include <stdio.h>
#include <time.h>

/*
 * Lightweight timing helpers shared by the bench/ programs. These are
 * intentionally simple wall-clock loop benchmarks, not a statistical
 * benchmarking framework: each bench program runs a fixed iteration count
 * and reports throughput, which is enough to catch gross regressions or
 * compare before/after changes locally.
 */
static inline double bench_now_seconds(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static inline void bench_report(const char *name, size_t iterations, double elapsed_seconds) {
    double ops_per_sec = elapsed_seconds > 0.0 ? (double)iterations / elapsed_seconds : 0.0;
    double ns_per_op = iterations > 0 ? (elapsed_seconds * 1e9) / (double)iterations : 0.0;

    printf("%-32s %10zu iters  %8.4f s  %14.0f ops/sec  %10.1f ns/op\n", name, iterations,
           elapsed_seconds, ops_per_sec, ns_per_op);
}

#endif
