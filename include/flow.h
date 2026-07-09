#ifndef FLOW_H
#define FLOW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"
#include "tcp_reassembly.h"

typedef struct {
    int family;
    uint8_t bytes[16];
} IPAddress;

/*
 * FlowKey identifies one transport conversation.
 * For TCP, endpoint A/B are normalized so packets from either direction use
 * the same key. Other transports can keep their packet direction order.
 */
typedef struct {
    IPAddress a_ip;
    uint16_t a_port;
    IPAddress b_ip;
    uint16_t b_port;
    uint8_t transport_protocol;
} FlowKey;

/*
 * Direction is relative to the normalized FlowKey endpoints.
 */
typedef enum { FLOW_DIR_A_TO_B = 0, FLOW_DIR_B_TO_A = 1 } FlowDirection;

/*
 * Per-direction counters are kept separate from aggregate counters so TCP
 * stream state can be attached here later without changing FlowInfo's shape.
 */
typedef struct {
    uint64_t packet_count;
    uint64_t byte_count;
    TcpReassemblyDirection tcp;
} FlowDirectionState;

/*
 * FlowInfo owns classification state for a conversation.
 * Each direction also owns bounded TCP reassembly state for stream-aware app
 * decoding.
 */
typedef struct {
    FlowKey key;
    uint64_t created_time;
    uint64_t last_seen_time;
    uint64_t packet_count;
    uint64_t byte_count;
    AppInfo app;
    AppDecodeStatus app_decode_status;
    bool app_classified;
    bool app_event_printed;
    size_t stream_buffer_bytes;
    FlowDirectionState directions[2];
} FlowInfo;

/*
 * Bounded in-memory flow table.
 * The current implementation uses a compact array because max_flows is capped
 * by configuration and the table will be easy to replace behind this API if a
 * hash table becomes necessary.
 *
 * The lifetime counters below accumulate contributions from flows that have
 * already left the table (see flow_table_snapshot_stats), so totals remain
 * accurate across eviction instead of being lost when a FlowInfo slot is
 * reused.
 */
typedef struct {
    FlowInfo *flows;
    size_t count;
    size_t max_flows;
    size_t stream_buffer_bytes;
    uint32_t timeout_seconds;

    uint64_t flows_created;
    uint64_t flows_closed_fin;
    uint64_t flows_closed_rst;
    uint64_t flows_evicted_idle;
    uint64_t flows_evicted_capacity;
    uint64_t retransmissions_total;
    uint64_t out_of_order_segments_total;
    uint64_t overlapping_segments_total;
    uint64_t gaps_total;
} FlowTable;

/*
 * Point-in-time summary of flow table activity and current reassembly memory
 * usage. Counters combine already-evicted flows' lifetime totals with the
 * live per-direction counters of flows still active in the table, so callers
 * do not need to query before every eviction to get an accurate total.
 */
typedef struct {
    uint64_t flows_created;
    uint64_t flows_active;
    uint64_t flows_closed_fin;
    uint64_t flows_closed_rst;
    uint64_t flows_evicted_idle;
    uint64_t flows_evicted_capacity;
    uint64_t retransmissions;
    uint64_t out_of_order_segments;
    uint64_t overlapping_segments;
    uint64_t gaps;
    size_t stream_bytes_in_use;
    size_t stream_bytes_configured_max;
} FlowTableStats;

/*
 * Initializes a bounded flow table.
 * Returns false when allocation fails or max_flows is zero.
 */
bool flow_table_init(FlowTable *table, size_t max_flows, size_t stream_buffer_bytes,
                     uint32_t timeout_seconds);

/*
 * Releases all memory owned by a flow table.
 */
void flow_table_cleanup(FlowTable *table);

/*
 * Builds a flow key from packet endpoint metadata.
 * TCP keys are normalized so both directions map to one flow.
 */
bool flow_key_from_packet(const PacketInfo *packet, FlowKey *key, FlowDirection *direction);

/*
 * Looks up an existing flow or creates one after idle/capacity eviction.
 * Returns NULL if no slot is available.
 */
FlowInfo *flow_table_get_or_create(FlowTable *table, const PacketInfo *packet, uint64_t now_seconds,
                                   FlowDirection *direction);

/*
 * Updates packet/byte counters and last-seen time for one packet.
 */
void flow_update_packet(FlowInfo *flow, const PacketInfo *packet, uint64_t now_seconds,
                        FlowDirection direction);

/* Lazily allocates reassembly storage for one active TCP direction. */
bool flow_prepare_reassembly_direction(FlowInfo *flow, FlowDirection direction);

/*
 * A flow is closed when either direction has seen RST (abrupt termination) or
 * both directions have seen FIN (graceful bidirectional close). NULL is never
 * closed.
 */
bool flow_is_closed(const FlowInfo *flow);

/*
 * Frees any reassembly buffers already allocated for a flow while preserving
 * FIN/RST and sequence tracking state. Call once a flow's app metadata has
 * been classified, since the buffered bytes are no longer read by anything.
 */
void flow_release_reassembly_buffers(FlowInfo *flow);

/*
 * Removes flows that have been idle at least timeout_seconds.
 */
void flow_table_evict_idle(FlowTable *table, uint64_t now_seconds);

/*
 * Removes flows that are fully closed (see flow_is_closed), reclaiming their
 * reassembly memory before the idle timeout would otherwise apply.
 */
void flow_table_evict_closed(FlowTable *table);

/*
 * Computes a point-in-time summary of flow table activity and current
 * reassembly memory usage. Read-only; safe to call at any time.
 */
FlowTableStats flow_table_snapshot_stats(const FlowTable *table);

#endif
