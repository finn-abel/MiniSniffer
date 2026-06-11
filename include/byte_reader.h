#ifndef BYTE_READER_H
#define BYTE_READER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const uint8_t *data;
    size_t length;
    size_t offset;
} ByteReader;

/*
 * Initializes a bounded reader over raw network bytes.
 * A NULL data pointer creates an empty reader.
 */
void br_init(ByteReader *reader, const uint8_t *data, size_t length);

/*
 * Returns true when at least needed bytes remain unread.
 */
bool br_remaining(const ByteReader *reader, size_t needed);

/*
 * Reads one unsigned byte and advances the reader.
 * Returns false and leaves the reader unchanged when data is unavailable.
 */
bool br_read_u8(ByteReader *reader, uint8_t *out);

/*
 * Reads a two-byte big-endian integer and advances the reader.
 * Returns false and leaves the reader unchanged on short input.
 */
bool br_read_u16_be(ByteReader *reader, uint16_t *out);

/*
 * Reads a four-byte big-endian integer and advances the reader.
 * Returns false and leaves the reader unchanged on short input.
 */
bool br_read_u32_be(ByteReader *reader, uint32_t *out);

/*
 * Advances the reader by count bytes without exposing them.
 * Returns false and leaves the reader unchanged on short input.
 */
bool br_skip(ByteReader *reader, size_t count);

#endif
