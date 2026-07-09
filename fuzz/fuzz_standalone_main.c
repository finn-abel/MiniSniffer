#include <stdio.h>
#include <stdlib.h>

#include "fuzz_common.h"

#define FUZZ_STANDALONE_MAX_FILE_BYTES (10 * 1024 * 1024)

/*
 * Reads one file fully into a heap buffer. Returns the byte count and sets
 * *out_data, or returns -1 and leaves *out_data untouched on any failure
 * (unreadable file, oversized file, short read).
 */
static long read_file(const char *path, uint8_t **out_data) {
    FILE *file;
    long file_size;
    uint8_t *buffer;
    size_t read_bytes;

    file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "fuzz-smoke: skipping unreadable file '%s'\n", path);
        return -1;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -1;
    }
    file_size = ftell(file);
    if (file_size < 0 || file_size > FUZZ_STANDALONE_MAX_FILE_BYTES) {
        fclose(file);
        fprintf(stderr, "fuzz-smoke: skipping oversized or unreadable file '%s'\n", path);
        return -1;
    }
    rewind(file);

    buffer = malloc(file_size > 0 ? (size_t)file_size : 1);
    if (buffer == NULL) {
        fclose(file);
        return -1;
    }

    read_bytes = fread(buffer, 1, (size_t)file_size, file);
    fclose(file);
    if ((long)read_bytes != file_size) {
        free(buffer);
        return -1;
    }

    *out_data = buffer;
    return file_size;
}

/*
 * Minimal libFuzzer-compatible replay driver. Real fuzzing (corpus mutation
 * driven by coverage feedback) requires linking the harness with
 * -fsanitize=fuzzer instead, which supplies its own main; this driver lets
 * the identical harness still be smoke-tested (every seed corpus file
 * replayed once, under AddressSanitizer/UndefinedBehaviorSanitizer) on
 * toolchains where a libFuzzer runtime is not available.
 */
int main(int argc, char **argv) {
    int i;
    long total_bytes = 0;
    int replayed = 0;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <corpus-file>...\n", argv[0]);
        return 0;
    }

    for (i = 1; i < argc; i++) {
        uint8_t *data = NULL;
        long file_size = read_file(argv[i], &data);

        if (file_size < 0) {
            continue;
        }
        LLVMFuzzerTestOneInput(data, (size_t)file_size);
        free(data);
        total_bytes += file_size;
        replayed++;
    }

    printf("fuzz-smoke: replayed %d file(s), %ld byte(s) total, no crashes.\n", replayed,
           total_bytes);
    return 0;
}
