#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "stream_buffer.h"

static void test_stream_buffer_appends_within_cap(void) {
    StreamBuffer buffer;

    assert(stream_buffer_init(&buffer, 8));
    assert(stream_buffer_append(&buffer, (const uint8_t *)"GET", 3));
    assert(stream_buffer_length(&buffer) == 3);
    assert(memcmp(stream_buffer_data(&buffer), "GET", 3) == 0);
    stream_buffer_cleanup(&buffer);
}

static void test_stream_buffer_rejects_growth_beyond_cap(void) {
    StreamBuffer buffer;

    assert(stream_buffer_init(&buffer, 4));
    assert(stream_buffer_append(&buffer, (const uint8_t *)"ABCD", 4));
    assert(!stream_buffer_append(&buffer, (const uint8_t *)"E", 1));
    assert(stream_buffer_length(&buffer) == 4);
    stream_buffer_cleanup(&buffer);
}

static void test_stream_buffer_compacts_consumed_bytes(void) {
    StreamBuffer buffer;

    assert(stream_buffer_init(&buffer, 6));
    assert(stream_buffer_append(&buffer, (const uint8_t *)"ABCDEF", 6));
    stream_buffer_consume(&buffer, 4);
    assert(stream_buffer_append(&buffer, (const uint8_t *)"GH", 2));
    assert(stream_buffer_length(&buffer) == 4);
    assert(memcmp(stream_buffer_data(&buffer), "EFGH", 4) == 0);
    stream_buffer_cleanup(&buffer);
}

int main(void) {
    test_stream_buffer_appends_within_cap();
    test_stream_buffer_rejects_growth_beyond_cap();
    test_stream_buffer_compacts_consumed_bytes();

    printf("All stream buffer tests passed.\n");

    return 0;
}
