#ifndef FLOW_H
#define FLOW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"
#include "tcp_reassembly.h"

/*
 * MiniSniffer currently tracks IPv4 flows only because PacketInfo stores
 * parsed endpoints as IPv4 text. The host-order integer form makes flow key
 * comparison independent of presentation formatting.
 */
typedef struct {
    uint32_t ipv4;
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
 */
typedef struct {
    FlowInfo *flows;
    size_t count;
    size_t max_flows;
    size_t stream_buffer_bytes;
    uint32_t timeout_seconds;
} FlowTable;

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
 * Removes flows that have been idle at least timeout_seconds.
 */
void flow_table_evict_idle(FlowTable *table, uint64_t now_seconds);

#endif
