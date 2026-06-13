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

static void test_stream_buffer_handles_invalid_inputs(void) {
    StreamBuffer buffer;

    assert(!stream_buffer_init(NULL, 4));
    assert(!stream_buffer_init(&buffer, 0));

    memset(&buffer, 0, sizeof(buffer));
    assert(!stream_buffer_append(NULL, (const uint8_t *)"A", 1));
    assert(!stream_buffer_append(&buffer, (const uint8_t *)"A", 1));
    assert(stream_buffer_data(NULL) == NULL);
    assert(stream_buffer_data(&buffer) == NULL);
    assert(stream_buffer_length(NULL) == 0);
    stream_buffer_consume(NULL, 1);
    stream_buffer_cleanup(NULL);
    stream_buffer_clear(NULL);
}

static void test_stream_buffer_handles_empty_and_oversized_appends(void) {
    StreamBuffer buffer;

    assert(stream_buffer_init(&buffer, 4));
    assert(stream_buffer_append(&buffer, NULL, 0));
    assert(!stream_buffer_append(&buffer, NULL, 1));
    assert(!stream_buffer_append(&buffer, (const uint8_t *)"ABCDE", 5));
    stream_buffer_cleanup(&buffer);
}

static void test_stream_buffer_consume_and_clear_reset_window(void) {
    StreamBuffer buffer;

    assert(stream_buffer_init(&buffer, 8));
    assert(stream_buffer_append(&buffer, (const uint8_t *)"ABCDEFGH", 8));
    stream_buffer_consume(&buffer, 1);
    assert(stream_buffer_length(&buffer) == 7);
    assert(*stream_buffer_data(&buffer) == 'B');

    stream_buffer_clear(&buffer);
    assert(stream_buffer_length(&buffer) == 0);
    assert(stream_buffer_data(&buffer) == NULL);
    assert(stream_buffer_append(&buffer, (const uint8_t *)"XY", 2));

    stream_buffer_consume(&buffer, 2);
    assert(stream_buffer_length(&buffer) == 0);
    assert(stream_buffer_data(&buffer) == NULL);
    stream_buffer_cleanup(&buffer);
}

static void test_stream_buffer_append_compacts_fully_consumed_state(void) {
    StreamBuffer buffer;

    assert(stream_buffer_init(&buffer, 4));
    assert(stream_buffer_append(&buffer, (const uint8_t *)"ABCD", 4));
    buffer.consumed = buffer.length;
    assert(stream_buffer_append(&buffer, (const uint8_t *)"Z", 1));
    assert(stream_buffer_length(&buffer) == 1);
    assert(*stream_buffer_data(&buffer) == 'Z');
    stream_buffer_cleanup(&buffer);
}

int main(void) {
    test_stream_buffer_appends_within_cap();
    test_stream_buffer_rejects_growth_beyond_cap();
    test_stream_buffer_compacts_consumed_bytes();
    test_stream_buffer_handles_invalid_inputs();
    test_stream_buffer_handles_empty_and_oversized_appends();
    test_stream_buffer_consume_and_clear_reset_window();
    test_stream_buffer_append_compacts_fully_consumed_state();

    printf("All stream buffer tests passed.\n");

    return 0;
}
