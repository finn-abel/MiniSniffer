#ifndef STREAM_BUFFER_H
#define STREAM_BUFFER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * StreamBuffer stores a bounded contiguous byte window for one flow direction.
 * Reassembly appends accepted TCP data here, and app decoders read the stable
 * buffer view without owning or copying it.
 */
typedef struct {
    uint8_t *data;
    size_t length;
    size_t consumed;
    size_t capacity;
} StreamBuffer;

/*
 * Allocates a fixed-capacity buffer. A zero capacity is invalid because stream
 * mode must have an explicit memory bound.
 */
bool stream_buffer_init(StreamBuffer *buffer, size_t capacity);

/*
 * Releases owned memory and resets the buffer to an empty state.
 */
void stream_buffer_cleanup(StreamBuffer *buffer);

/*
 * Appends bytes without growing beyond capacity.
 * Returns false when the new data cannot fit after compaction.
 */
bool stream_buffer_append(StreamBuffer *buffer, const uint8_t *data, size_t length);

/*
 * Marks bytes as consumed and compacts storage when useful.
 */
void stream_buffer_consume(StreamBuffer *buffer, size_t length);

/*
 * Returns a pointer to readable unconsumed bytes.
 */
const uint8_t *stream_buffer_data(const StreamBuffer *buffer);

/*
 * Returns the number of readable unconsumed bytes.
 */
size_t stream_buffer_length(const StreamBuffer *buffer);

/*
 * Removes all buffered bytes while keeping allocated capacity.
 */
void stream_buffer_clear(StreamBuffer *buffer);

#endif
