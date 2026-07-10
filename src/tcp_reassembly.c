#include <stdlib.h>
#include <string.h>

#include "tcp_reassembly.h"

/* Payload begins one sequence number after SYN when SYN carries data. */
static uint32_t payload_sequence(uint32_t sequence, uint8_t flags) {
    return (flags & TCP_FLAG_SYN) != 0 ? sequence + 1 : sequence;
}

/* TCP sequence numbers use serial-number arithmetic, not ordinary integers. */
static bool sequence_before(uint32_t left, uint32_t right) {
    return (int32_t)(left - right) < 0;
}

static bool sequence_before_or_equal(uint32_t left, uint32_t right) {
    return left == right || sequence_before(left, right);
}

/*
 * Pending out-of-order segments own copied payload bytes because the original
 * packet memory is only valid during capture callback processing.
 */
static void clear_pending_segment(TcpOutOfOrderSegment *segment) {
    if (segment == NULL) {
        return;
    }

    free(segment->data);
    memset(segment, 0, sizeof(*segment));
}

/*
 * Keep pending segments compact after removal. The small fixed pending array
 * favors predictable memory over complex indexing.
 */
static void remove_pending_at(TcpReassemblyDirection *state, size_t index) {
    if (state == NULL || index >= state->pending_count) {
        return;
    }

    if (state->pending[index].length <= state->pending_bytes) {
        state->pending_bytes -= state->pending[index].length;
    } else {
        state->pending_bytes = 0;
    }
    clear_pending_segment(&state->pending[index]);
    if (index + 1 < state->pending_count) {
        memmove(&state->pending[index], &state->pending[index + 1],
                (state->pending_count - index - 1) * sizeof(state->pending[0]));
    }
    state->pending_count--;
    memset(&state->pending[state->pending_count], 0, sizeof(state->pending[0]));
}

static bool append_stream_data(TcpReassemblyDirection *state, const uint8_t *data, size_t length) {
    return stream_buffer_append(&state->stream, data, length);
}

/*
 * Appends as much of an in-order segment as the fixed buffer can still hold and
 * returns the number of bytes stored. A short return means the buffer filled
 * mid-segment: callers keep the contiguous head that fit (enough to decode the
 * start of a stream) and then stop reassembling the direction, so no later
 * segment is ever spliced onto the byte the truncation dropped.
 */
static size_t append_stream_best_effort(TcpReassemblyDirection *state, const uint8_t *data,
                                        size_t length) {
    size_t room = state->stream.capacity - stream_buffer_length(&state->stream);
    size_t take = length < room ? length : room;

    if (take == 0 || !append_stream_data(state, data, take)) {
        return 0;
    }
    return take;
}

/*
 * After in-order data advances next_sequence, previously buffered segments may
 * now fit. Re-run until no pending segment can extend the contiguous stream.
 */
static bool flush_pending_segments(TcpReassemblyDirection *state) {
    bool advanced = true;

    while (advanced) {
        size_t i;

        advanced = false;
        for (i = 0; i < state->pending_count; i++) {
            TcpOutOfOrderSegment *segment = &state->pending[i];
            uint32_t segment_end = segment->sequence + (uint32_t)segment->length;

            if (sequence_before_or_equal(segment_end, state->next_sequence)) {
                state->retransmissions++;
                remove_pending_at(state, i);
                advanced = true;
                break;
            }
            if (sequence_before_or_equal(segment->sequence, state->next_sequence)) {
                size_t trim = (size_t)(state->next_sequence - segment->sequence);

                /*
                 * Overlap policy is "keep first bytes, trim later bytes." This
                 * is simple, deterministic, and avoids rewriting stream data.
                 */
                if (trim > 0) {
                    state->overlapping_segments++;
                }
                if (!append_stream_data(state, segment->data + trim, segment->length - trim)) {
                    state->unusable = true;
                    return false;
                }
                state->next_sequence = segment_end;
                remove_pending_at(state, i);
                advanced = true;
                break;
            }
        }
    }

    return true;
}

/*
 * Out-of-order payload is copied into a bounded side buffer. Both segment count
 * and total bytes are capped so a flow cannot accumulate unbounded gaps.
 */
static bool store_out_of_order_segment(TcpReassemblyDirection *state, uint32_t sequence,
                                       const uint8_t *payload, size_t payload_length) {
    TcpOutOfOrderSegment *segment;

    if (state->pending_count >= TCP_REASSEMBLY_MAX_PENDING_SEGMENTS || payload == NULL ||
        payload_length == 0 || payload_length > state->pending_byte_cap ||
        payload_length > state->pending_byte_cap - state->pending_bytes) {
        return false;
    }

    segment = &state->pending[state->pending_count];
    memset(segment, 0, sizeof(*segment));
    segment->data = malloc(payload_length);
    if (segment->data == NULL) {
        return false;
    }

    memcpy(segment->data, payload, payload_length);
    segment->sequence = sequence;
    segment->length = payload_length;
    state->pending_count++;
    state->pending_bytes += payload_length;
    return true;
}

/*
 * Use the same configured byte cap for contiguous stream bytes and pending
 * out-of-order bytes. It is conservative but easy to reason about.
 */
bool tcp_reassembly_direction_init(TcpReassemblyDirection *state, size_t stream_buffer_bytes) {
    if (state == NULL || stream_buffer_bytes == 0) {
        return false;
    }

    memset(state, 0, sizeof(*state));
    if (!stream_buffer_init(&state->stream, stream_buffer_bytes)) {
        return false;
    }
    state->pending_byte_cap = stream_buffer_bytes;
    return true;
}

/*
 * Free every copied pending payload before releasing the contiguous stream.
 */
void tcp_reassembly_direction_cleanup(TcpReassemblyDirection *state) {
    size_t i;

    if (state == NULL) {
        return;
    }

    for (i = 0; i < state->pending_count; i++) {
        clear_pending_segment(&state->pending[i]);
    }
    stream_buffer_cleanup(&state->stream);
    memset(state, 0, sizeof(*state));
}

/*
 * FIN/RST are sticky facts about a direction that must remain observable even
 * after buffered reassembly stops, so this never depends on sequence state or
 * the stream/pending stores.
 */
void tcp_reassembly_track_flags(TcpReassemblyDirection *state, uint8_t flags) {
    if (state == NULL) {
        return;
    }

    if ((flags & TCP_FLAG_RST) != 0) {
        state->rst_seen = true;
    }
    if ((flags & TCP_FLAG_FIN) != 0) {
        state->fin_seen = true;
    }
}

/*
 * Reclaims memory for a direction that no longer needs buffered bytes (for
 * example, once its flow has already been classified). Tracking fields are
 * preserved so tcp_reassembly_track_flags keeps working afterward.
 */
void tcp_reassembly_direction_release_buffers(TcpReassemblyDirection *state) {
    size_t i;

    if (state == NULL) {
        return;
    }

    for (i = 0; i < state->pending_count; i++) {
        clear_pending_segment(&state->pending[i]);
    }
    state->pending_count = 0;
    state->pending_bytes = 0;
    stream_buffer_cleanup(&state->stream);
}

/*
 * This is intentionally a modest TCP reconstructor: accept in-order data,
 * buffer simple future data, trim overlaps, and drop anything that would exceed
 * fixed memory caps. It does not try to model every TCP edge case yet.
 */
TcpReassemblyResult tcp_reassembly_process_segment(TcpReassemblyDirection *state, uint32_t sequence,
                                                   uint8_t flags, const uint8_t *payload,
                                                   size_t payload_length) {
    uint32_t data_sequence;
    uint32_t segment_end;

    if (state == NULL || state->unusable) {
        return TCP_REASSEMBLY_DROPPED;
    }

    if ((flags & TCP_FLAG_RST) != 0) {
        state->rst_seen = true;
    }
    if ((flags & TCP_FLAG_FIN) != 0) {
        state->fin_seen = true;
    }

    if (!state->initial_sequence_known) {
        /*
         * If capture starts mid-stream, the first segment becomes our baseline.
         * Later gaps and retransmits are interpreted relative to this point.
         */
        state->next_sequence = payload_sequence(sequence, flags);
        state->initial_sequence_known = true;
    }

    if (payload_length == 0) {
        if ((flags & TCP_FLAG_FIN) != 0 &&
            state->next_sequence == payload_sequence(sequence, flags)) {
            state->next_sequence++;
        }
        return TCP_REASSEMBLY_ACCEPTED;
    }
    if (payload == NULL || payload_length > UINT32_MAX) {
        state->unusable = true;
        return TCP_REASSEMBLY_DROPPED;
    }

    data_sequence = payload_sequence(sequence, flags);
    segment_end = data_sequence + (uint32_t)payload_length;

    if (sequence_before_or_equal(segment_end, state->next_sequence)) {
        state->retransmissions++;
        return TCP_REASSEMBLY_IGNORED;
    }

    if (sequence_before(state->next_sequence, data_sequence)) {
        /*
         * A future sequence means a gap exists. Keep the segment only if it can
         * fit in the bounded pending store.
         */
        state->out_of_order_segments++;
        state->gaps++;
        if (!store_out_of_order_segment(state, data_sequence, payload, payload_length)) {
            return TCP_REASSEMBLY_DROPPED;
        }
        return TCP_REASSEMBLY_BUFFERED;
    }

    if (sequence_before(data_sequence, state->next_sequence)) {
        size_t trim = (size_t)(state->next_sequence - data_sequence);

        /*
         * Overlapping retransmits do not overwrite earlier bytes. Any new tail
         * after the overlap is appended as normal in-order data.
         */
        state->overlapping_segments++;
        if (trim >= payload_length) {
            state->retransmissions++;
            return TCP_REASSEMBLY_IGNORED;
        }
        payload += trim;
        payload_length -= trim;
        data_sequence = state->next_sequence;
    }

    {
        size_t appended = append_stream_best_effort(state, payload, payload_length);

        if (appended < payload_length) {
            /*
             * The whole segment does not fit the fixed buffer. Keep the head
             * that fit so decoders still see the start of the stream, then mark
             * the direction unusable: refusing further data prevents a later
             * segment from being spliced onto the truncated tail. ACCEPTED (not
             * DROPPED) when any head was captured lets the caller decode it.
             */
            state->unusable = true;
            return appended > 0 ? TCP_REASSEMBLY_ACCEPTED : TCP_REASSEMBLY_DROPPED;
        }
    }
    state->next_sequence = data_sequence + (uint32_t)payload_length;
    if ((flags & TCP_FLAG_FIN) != 0) {
        state->next_sequence++;
    }
    if (!flush_pending_segments(state)) {
        return TCP_REASSEMBLY_DROPPED;
    }

    return TCP_REASSEMBLY_ACCEPTED;
}
