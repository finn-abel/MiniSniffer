#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>

/*
 * Standard libFuzzer entry point. Each fuzz/fuzz_<name>.c file defines this
 * exactly once. fuzz_standalone_main.c declares the same prototype and calls
 * it directly, so the identical harness can be replayed over seed corpus
 * files without linking against a real libFuzzer runtime.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#endif
