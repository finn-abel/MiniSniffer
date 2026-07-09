#include "byte_reader.h"

/*
 * ByteReader never owns data; it only tracks a safe offset inside caller-owned
 * packet or stream buffers.
 */
void br_init(ByteReader *reader, const uint8_t *data, size_t length) {
    if (reader == NULL) {
        return;
    }

    reader->data = data;
    reader->length = data == NULL ? 0 : length;
    reader->offset = 0;
}

/*
 * Central bounds check used by every read/skip helper.
 * The subtraction is guarded so corrupted offsets cannot underflow.
 */
bool br_remaining(const ByteReader *reader, size_t needed) {
    if (reader == NULL || reader->data == NULL) {
        return false;
    }
    if (reader->offset > reader->length) {
        return false;
    }

    return needed <= reader->length - reader->offset;
}

bool br_read_u8(ByteReader *reader, uint8_t *out) {
    if (!br_remaining(reader, 1) || out == NULL) {
        return false;
    }

    *out = reader->data[reader->offset];
    reader->offset++;
    return true;
}

/*
 * Multi-byte reads check the full width before advancing, making failures
 * all-or-nothing for protocol decoders.
 */
bool br_read_u16_be(ByteReader *reader, uint16_t *out) {
    if (out == NULL || !br_remaining(reader, 2)) {
        return false;
    }

    *out = (uint16_t)(((uint16_t)reader->data[reader->offset] << 8) |
                      reader->data[reader->offset + 1]);
    reader->offset += 2;
    return true;
}

/*
 * Network protocol integer fields are read explicitly as big-endian bytes so
 * callers never rely on host alignment or host byte order.
 */
bool br_read_u32_be(ByteReader *reader, uint32_t *out) {
    if (out == NULL || !br_remaining(reader, 4)) {
        return false;
    }

    *out = ((uint32_t)reader->data[reader->offset] << 24) |
           ((uint32_t)reader->data[reader->offset + 1] << 16) |
           ((uint32_t)reader->data[reader->offset + 2] << 8) | reader->data[reader->offset + 3];
    reader->offset += 4;
    return true;
}

bool br_skip(ByteReader *reader, size_t count) {
    if (!br_remaining(reader, count)) {
        return false;
    }

    reader->offset += count;
    return true;
}
