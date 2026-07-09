#ifndef TCP_REASSEMBLY_H
#define TCP_REASSEMBLY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "stream_buffer.h"

#define TCP_REASSEMBLY_MAX_PENDING_SEGMENTS 8

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04

typedef enum {
    TCP_REASSEMBLY_ACCEPTED = 0,
    TCP_REASSEMBLY_BUFFERED,
    TCP_REASSEMBLY_IGNORED,
    TCP_REASSEMBLY_DROPPED
} TcpReassemblyResult;

typedef struct {
    uint32_t sequence;
    size_t length;
    uint8_t *data;
} TcpOutOfOrderSegment;

/*
 * TcpReassemblyDirection tracks sequence state and a bounded readable stream
 * for one direction of a TCP flow.
 */
typedef struct {
    uint32_t next_sequence;
    bool initial_sequence_known;
    bool fin_seen;
    bool rst_seen;
    bool unusable;

    uint64_t out_of_order_segments;
    uint64_t retransmissions;
    uint64_t overlapping_segments;
    uint64_t gaps;

    StreamBuffer stream;
    TcpOutOfOrderSegment pending[TCP_REASSEMBLY_MAX_PENDING_SEGMENTS];
    size_t pending_count;
    size_t pending_bytes;
    size_t pending_byte_cap;
} TcpReassemblyDirection;

/*
 * Initializes one direction with a fixed stream/pending memory cap.
 */
bool tcp_reassembly_direction_init(TcpReassemblyDirection *state, size_t stream_buffer_bytes);

/*
 * Releases stream and pending-segment memory owned by one direction.
 */
void tcp_reassembly_direction_cleanup(TcpReassemblyDirection *state);

/*
 * Processes one TCP segment payload using conservative in-order reconstruction.
 * In-order data is appended to state->stream; simple out-of-order data is held
 * until gaps are filled, subject to the same configured memory cap.
 */
TcpReassemblyResult tcp_reassembly_process_segment(TcpReassemblyDirection *state, uint32_t sequence,
                                                   uint8_t flags, const uint8_t *payload,
                                                   size_t payload_length);

#endif
