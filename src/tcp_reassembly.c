#include <stdlib.h>
#include <string.h>

#include "tcp_reassembly.h"

/*
 * SYN and FIN each consume one sequence number even when they do not carry
 * payload bytes. Tracking that early keeps first data aligned after handshakes.
 */
static uint32_t sequence_after_segment(uint32_t sequence, uint8_t flags, size_t payload_length) {
    uint32_t next = sequence;

    if ((flags & TCP_FLAG_SYN) != 0) {
        next++;
    }
    next += (uint32_t)payload_length;
    if ((flags & TCP_FLAG_FIN) != 0) {
        next++;
    }

    return next;
}

/*
 * Payload begins one sequence number after SYN when SYN and data share a
 * segment. Normal data segments start exactly at their TCP sequence number.
 */
static uint32_t payload_sequence(uint32_t sequence, uint8_t flags) {
    return (flags & TCP_FLAG_SYN) != 0 ? sequence + 1 : sequence;
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
        memmove(&state->pending[index],
                &state->pending[index + 1],
                (state->pending_count - index - 1) * sizeof(state->pending[0]));
    }
    state->pending_count--;
    memset(&state->pending[state->pending_count], 0, sizeof(state->pending[0]));
}

static bool append_stream_data(TcpReassemblyDirection *state, const uint8_t *data, size_t length) {
    return stream_buffer_append(&state->stream, data, length);
}

/*
 * After in-order data advances next_sequence, previously buffered segments may
 * now fit. Re-run until no pending segment can extend the contiguous stream.
 */
static void flush_pending_segments(TcpReassemblyDirection *state) {
    bool advanced = true;

    while (advanced) {
        size_t i;

        advanced = false;
        for (i = 0; i < state->pending_count; i++) {
            TcpOutOfOrderSegment *segment = &state->pending[i];
            uint32_t segment_end = segment->sequence + (uint32_t)segment->length;

            if (segment_end <= state->next_sequence) {
                state->retransmissions++;
                remove_pending_at(state, i);
                advanced = true;
                break;
            }
            if (segment->sequence <= state->next_sequence) {
                size_t trim = (size_t)(state->next_sequence - segment->sequence);

                /*
                 * Overlap policy is "keep first bytes, trim later bytes." This
                 * is simple, deterministic, and avoids rewriting stream data.
                 */
                if (trim > 0) {
                    state->overlapping_segments++;
                }
                if (!append_stream_data(state, segment->data + trim, segment->length - trim)) {
                    return;
                }
                state->next_sequence = segment_end;
                remove_pending_at(state, i);
                advanced = true;
                break;
            }
        }
    }
}

/*
 * Out-of-order payload is copied into a bounded side buffer. Both segment count
 * and total bytes are capped so a flow cannot accumulate unbounded gaps.
 */
static bool store_out_of_order_segment(
    TcpReassemblyDirection *state,
    uint32_t sequence,
    const uint8_t *payload,
    size_t payload_length
) {
    TcpOutOfOrderSegment *segment;

    if (state->pending_count >= TCP_REASSEMBLY_MAX_PENDING_SEGMENTS ||
        payload == NULL ||
        payload_length == 0 ||
        payload_length > state->pending_byte_cap ||
        state->pending_bytes + payload_length > state->pending_byte_cap) {
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
 * This is intentionally a modest TCP reconstructor: accept in-order data,
 * buffer simple future data, trim overlaps, and drop anything that would exceed
 * fixed memory caps. It does not try to model every TCP edge case yet.
 */
TcpReassemblyResult tcp_reassembly_process_segment(
    TcpReassemblyDirection *state,
    uint32_t sequence,
    uint8_t flags,
    const uint8_t *payload,
    size_t payload_length
) {
    uint32_t data_sequence;
    uint32_t segment_end;

    if (state == NULL) {
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
        state->next_sequence = sequence_after_segment(sequence, flags, 0);
        state->initial_sequence_known = true;
    }

    if (payload_length == 0) {
        return TCP_REASSEMBLY_ACCEPTED;
    }
    if (payload == NULL || payload_length > state->stream.capacity) {
        return TCP_REASSEMBLY_DROPPED;
    }

    data_sequence = payload_sequence(sequence, flags);
    segment_end = data_sequence + (uint32_t)payload_length;

    if (segment_end <= state->next_sequence) {
        state->retransmissions++;
        return TCP_REASSEMBLY_IGNORED;
    }

    if (data_sequence > state->next_sequence) {
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

    if (data_sequence < state->next_sequence) {
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

    if (!append_stream_data(state, payload, payload_length)) {
        return TCP_REASSEMBLY_DROPPED;
    }
    state->next_sequence = data_sequence + (uint32_t)payload_length;
    flush_pending_segments(state);

    return TCP_REASSEMBLY_ACCEPTED;
}
