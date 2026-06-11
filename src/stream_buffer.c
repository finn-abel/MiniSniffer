#include <stdlib.h>
#include <string.h>

#include "stream_buffer.h"

/*
 * Compaction preserves only unread bytes and resets consumed accounting.
 * This is the only way append can reclaim space; the buffer never reallocates.
 */
static void compact_buffer(StreamBuffer *buffer) {
    if (buffer == NULL || buffer->consumed == 0) {
        return;
    }

    if (buffer->consumed >= buffer->length) {
        buffer->length = 0;
        buffer->consumed = 0;
        return;
    }

    memmove(buffer->data,
            buffer->data + buffer->consumed,
            buffer->length - buffer->consumed);
    buffer->length -= buffer->consumed;
    buffer->consumed = 0;
}

/*
 * Allocate one fixed backing store up front so stream buffering has a hard
 * per-direction memory ceiling.
 */
bool stream_buffer_init(StreamBuffer *buffer, size_t capacity) {
    if (buffer == NULL || capacity == 0) {
        return false;
    }

    memset(buffer, 0, sizeof(*buffer));
    buffer->data = malloc(capacity);
    if (buffer->data == NULL) {
        return false;
    }

    buffer->capacity = capacity;
    return true;
}

/*
 * Cleanup accepts partially initialized buffers, which keeps flow cleanup safe
 * during allocation failures or table eviction.
 */
void stream_buffer_cleanup(StreamBuffer *buffer) {
    if (buffer == NULL) {
        return;
    }

    free(buffer->data);
    memset(buffer, 0, sizeof(*buffer));
}

/*
 * Append is conservative: it compacts consumed bytes once, then refuses data
 * that still does not fit. That gives callers a clear NEED_MORE/drop boundary
 * without hidden growth.
 */
bool stream_buffer_append(StreamBuffer *buffer, const uint8_t *data, size_t length) {
    if (buffer == NULL || buffer->data == NULL) {
        return false;
    }
    if (length == 0) {
        return true;
    }
    if (data == NULL || length > buffer->capacity) {
        return false;
    }

    if (buffer->length + length > buffer->capacity) {
        compact_buffer(buffer);
    }
    if (buffer->length + length > buffer->capacity) {
        return false;
    }

    memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
    return true;
}

/*
 * Consumption is logical first. Physical compaction happens only when enough
 * front space has accumulated, avoiding a memmove on every decoder advance.
 */
void stream_buffer_consume(StreamBuffer *buffer, size_t length) {
    size_t readable;

    if (buffer == NULL) {
        return;
    }

    readable = stream_buffer_length(buffer);
    if (length >= readable) {
        buffer->length = 0;
        buffer->consumed = 0;
        return;
    }

    buffer->consumed += length;
    if (buffer->consumed > buffer->capacity / 2) {
        compact_buffer(buffer);
    }
}

/*
 * Expose only unread bytes. NULL for an empty buffer lets callers pass the
 * result directly to decoders that treat NULL as no available stream data.
 */
const uint8_t *stream_buffer_data(const StreamBuffer *buffer) {
    if (buffer == NULL || buffer->data == NULL || buffer->consumed >= buffer->length) {
        return NULL;
    }

    return buffer->data + buffer->consumed;
}

/*
 * Length is always the readable window, not the raw allocation or total bytes
 * ever appended.
 */
size_t stream_buffer_length(const StreamBuffer *buffer) {
    if (buffer == NULL || buffer->consumed >= buffer->length) {
        return 0;
    }

    return buffer->length - buffer->consumed;
}

/*
 * Clear discards buffered content but keeps the fixed allocation for reuse by
 * the same flow direction.
 */
void stream_buffer_clear(StreamBuffer *buffer) {
    if (buffer == NULL) {
        return;
    }

    buffer->length = 0;
    buffer->consumed = 0;
}
