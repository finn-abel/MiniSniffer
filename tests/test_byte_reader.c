#include <assert.h>
#include <stdio.h>

#include "byte_reader.h"

static void test_byte_reader_reads_big_endian_values(void) {
    const uint8_t data[] = {0x12, 0x34, 0x56, 0x78, 0x9a};
    ByteReader reader;
    uint8_t value8;
    uint16_t value16;
    uint32_t value32;

    br_init(&reader, data, sizeof(data));

    assert(br_read_u8(&reader, &value8));
    assert(value8 == 0x12);
    assert(br_read_u16_be(&reader, &value16));
    assert(value16 == 0x3456);
    assert(br_read_u16_be(&reader, &value16));
    assert(value16 == 0x789a);
    assert(!br_read_u32_be(&reader, &value32));
}

static void test_byte_reader_skip_and_remaining_are_bounded(void) {
    const uint8_t data[] = {0xde, 0xad, 0xbe, 0xef};
    ByteReader reader;
    uint16_t value;

    br_init(&reader, data, sizeof(data));

    assert(br_remaining(&reader, 4));
    assert(!br_remaining(&reader, 5));
    assert(br_skip(&reader, 2));
    assert(br_read_u16_be(&reader, &value));
    assert(value == 0xbeef);
    assert(!br_skip(&reader, 1));
}

static void test_byte_reader_rejects_null_data(void) {
    ByteReader reader;
    uint8_t value;

    br_init(&reader, NULL, 12);

    assert(!br_remaining(&reader, 1));
    assert(!br_read_u8(&reader, &value));
}

static void test_byte_reader_handles_invalid_state_and_outputs(void) {
    const uint8_t data[] = {0x12, 0x34, 0x56, 0x78};
    ByteReader reader;
    uint32_t value32;

    br_init(NULL, data, sizeof(data));
    assert(!br_remaining(NULL, 0));

    br_init(&reader, data, sizeof(data));
    assert(!br_read_u8(&reader, NULL));
    assert(!br_read_u16_be(&reader, NULL));
    assert(!br_read_u32_be(&reader, NULL));
    assert(br_read_u32_be(&reader, &value32));
    assert(value32 == 0x12345678u);

    reader.offset = reader.length + 1;
    assert(!br_remaining(&reader, 0));
}

int main(void) {
    test_byte_reader_reads_big_endian_values();
    test_byte_reader_skip_and_remaining_are_bounded();
    test_byte_reader_rejects_null_data();
    test_byte_reader_handles_invalid_state_and_outputs();

    printf("All byte reader tests passed.\n");

    return 0;
}
