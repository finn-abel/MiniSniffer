#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "flow.h"

/*
 * Store protocol numbers in FlowKey using the IP protocol registry values.
 * That keeps flow identity independent from MiniSniffer's display enum names.
 */
static bool packet_protocol_to_flow_protocol(Protocol protocol, uint8_t *transport_protocol) {
    if (transport_protocol == NULL) {
        return false;
    }
    if (protocol == PROTO_TCP) {
        *transport_protocol = 6;
        return true;
    }
    if (protocol == PROTO_UDP) {
        *transport_protocol = 17;
        return true;
    }

    return false;
}

/*
 * PacketInfo carries addresses as printable strings for output. Convert once
 * at the flow boundary so comparisons and normalization are numeric.
 */
static bool parse_ip_address(const char *text, IPAddress *address) {
    struct in_addr parsed4;
    struct in6_addr parsed6;

    if (text == NULL || address == NULL) {
        return false;
    }

    memset(address, 0, sizeof(*address));
    if (inet_pton(AF_INET, text, &parsed4) == 1) {
        address->family = AF_INET;
        memcpy(address->bytes, &parsed4, sizeof(parsed4));
        return true;
    }
    if (inet_pton(AF_INET6, text, &parsed6) == 1) {
        address->family = AF_INET6;
        memcpy(address->bytes, &parsed6, sizeof(parsed6));
        return true;
    }

    return false;
}

/*
 * Endpoint ordering gives TCP a stable direction-independent identity.
 */
static int compare_endpoint(IPAddress left_ip, uint16_t left_port, IPAddress right_ip,
                            uint16_t right_port) {
    int address_order;

    if (left_ip.family < right_ip.family) {
        return -1;
    }
    if (left_ip.family > right_ip.family) {
        return 1;
    }
    address_order = memcmp(left_ip.bytes, right_ip.bytes, sizeof(left_ip.bytes));
    if (address_order != 0) {
        return address_order < 0 ? -1 : 1;
    }
    if (left_port < right_port) {
        return -1;
    }
    if (left_port > right_port) {
        return 1;
    }

    return 0;
}

/*
 * Flow keys are intentionally plain values, so equality is just field-by-field
 * comparison with no allocated ownership involved.
 */
static bool flow_key_equals(const FlowKey *left, const FlowKey *right) {
    return left->a_ip.family == right->a_ip.family &&
           memcmp(left->a_ip.bytes, right->a_ip.bytes, sizeof(left->a_ip.bytes)) == 0 &&
           left->a_port == right->a_port && left->b_ip.family == right->b_ip.family &&
           memcmp(left->b_ip.bytes, right->b_ip.bytes, sizeof(left->b_ip.bytes)) == 0 &&
           left->b_port == right->b_port &&
           left->transport_protocol == right->transport_protocol;
}

/*
 * Folds one direction's lifetime counters into the table before its state is
 * freed, so retransmission/gap/overlap totals survive flow eviction instead
 * of being lost when the FlowInfo slot is reused.
 */
static void accumulate_direction_totals(FlowTable *table, const TcpReassemblyDirection *tcp) {
    table->retransmissions_total += tcp->retransmissions;
    table->out_of_order_segments_total += tcp->out_of_order_segments;
    table->overlapping_segments_total += tcp->overlapping_segments;
    table->gaps_total += tcp->gaps;
}

/*
 * The array remains compact after eviction. This keeps iteration simple and
 * avoids leaving tombstones that would complicate max-flow accounting.
 */
static void remove_flow_at(FlowTable *table, size_t index) {
    if (table == NULL || index >= table->count) {
        return;
    }

    accumulate_direction_totals(table, &table->flows[index].directions[FLOW_DIR_A_TO_B].tcp);
    accumulate_direction_totals(table, &table->flows[index].directions[FLOW_DIR_B_TO_A].tcp);
    tcp_reassembly_direction_cleanup(&table->flows[index].directions[FLOW_DIR_A_TO_B].tcp);
    tcp_reassembly_direction_cleanup(&table->flows[index].directions[FLOW_DIR_B_TO_A].tcp);

    if (index + 1 < table->count) {
        memmove(&table->flows[index], &table->flows[index + 1],
                (table->count - index - 1) * sizeof(table->flows[0]));
    }
    table->count--;
}

/*
 * Allocate all flow slots up front so runtime packet processing never grows
 * memory beyond the configured max_flows cap.
 */
bool flow_table_init(FlowTable *table, size_t max_flows, size_t stream_buffer_bytes,
                     uint32_t timeout_seconds) {
    if (table == NULL || max_flows == 0 || stream_buffer_bytes == 0 ||
        max_flows > MINISNIFFER_MAX_FLOWS ||
        stream_buffer_bytes > MINISNIFFER_MAX_STREAM_BUFFER_BYTES ||
        max_flows > MINISNIFFER_MAX_TOTAL_REASSEMBLY_BYTES / 4 / stream_buffer_bytes) {
        return false;
    }

    memset(table, 0, sizeof(*table));
    table->flows = calloc(max_flows, sizeof(table->flows[0]));
    if (table->flows == NULL) {
        return false;
    }

    table->max_flows = max_flows;
    table->stream_buffer_bytes = stream_buffer_bytes;
    table->timeout_seconds = timeout_seconds;
    return true;
}

/*
 * Cleanup accepts partially initialized tables so callers can use one exit
 * path whether reassembly was enabled or setup failed early.
 */
void flow_table_cleanup(FlowTable *table) {
    size_t i;

    if (table == NULL) {
        return;
    }

    for (i = 0; i < table->count; i++) {
        tcp_reassembly_direction_cleanup(&table->flows[i].directions[FLOW_DIR_A_TO_B].tcp);
        tcp_reassembly_direction_cleanup(&table->flows[i].directions[FLOW_DIR_B_TO_A].tcp);
    }
    free(table->flows);
    memset(table, 0, sizeof(*table));
}

/*
 * Build identity from packet metadata only. Payload decoding and flow app
 * classification deliberately happen outside this function.
 */
bool flow_key_from_packet(const PacketInfo *packet, FlowKey *key, FlowDirection *direction) {
    IPAddress src_ip;
    IPAddress dst_ip;
    uint8_t transport_protocol;
    int ordering;

    if (packet == NULL || key == NULL || packet->has_ports == 0) {
        return false;
    }
    if (!packet_protocol_to_flow_protocol(packet->protocol, &transport_protocol) ||
        !parse_ip_address(packet->src_ip, &src_ip) || !parse_ip_address(packet->dst_ip, &dst_ip)) {
        return false;
    }

    memset(key, 0, sizeof(*key));
    key->transport_protocol = transport_protocol;

    /*
     * TCP is bidirectional by nature for the future stream table, so normalize
     * endpoints. UDP is left in packet order for now.
     */
    ordering = compare_endpoint(src_ip, packet->src_port, dst_ip, packet->dst_port);
    if (packet->protocol == PROTO_TCP && ordering > 0) {
        key->a_ip = dst_ip;
        key->a_port = packet->dst_port;
        key->b_ip = src_ip;
        key->b_port = packet->src_port;
        if (direction != NULL) {
            *direction = FLOW_DIR_B_TO_A;
        }
        return true;
    }

    key->a_ip = src_ip;
    key->a_port = packet->src_port;
    key->b_ip = dst_ip;
    key->b_port = packet->dst_port;
    if (direction != NULL) {
        *direction = FLOW_DIR_A_TO_B;
    }
    return true;
}

/*
 * Idle eviction is time based and independent of max-flow pressure. The loop
 * rechecks the same index after removal because entries shift left.
 */
void flow_table_evict_idle(FlowTable *table, uint64_t now_seconds) {
    size_t i = 0;

    if (table == NULL || table->flows == NULL || table->timeout_seconds == 0) {
        return;
    }

    while (i < table->count) {
        uint64_t idle_seconds = now_seconds >= table->flows[i].last_seen_time
                                    ? now_seconds - table->flows[i].last_seen_time
                                    : 0;

        if (idle_seconds >= table->timeout_seconds) {
            table->flows_evicted_idle++;
            remove_flow_at(table, i);
        } else {
            i++;
        }
    }
}

/*
 * A flow is closed when either direction has seen RST, or both directions
 * have seen FIN. This depends only on the sticky flags tracked by
 * tcp_reassembly_track_flags/tcp_reassembly_process_segment, so it stays
 * correct even after a flow's reassembly buffers have been released.
 */
bool flow_is_closed(const FlowInfo *flow) {
    const TcpReassemblyDirection *a_to_b;
    const TcpReassemblyDirection *b_to_a;

    if (flow == NULL) {
        return false;
    }

    a_to_b = &flow->directions[FLOW_DIR_A_TO_B].tcp;
    b_to_a = &flow->directions[FLOW_DIR_B_TO_A].tcp;
    if (a_to_b->rst_seen || b_to_a->rst_seen) {
        return true;
    }

    return a_to_b->fin_seen && b_to_a->fin_seen;
}

void flow_release_reassembly_buffers(FlowInfo *flow) {
    if (flow == NULL) {
        return;
    }

    tcp_reassembly_direction_release_buffers(&flow->directions[FLOW_DIR_A_TO_B].tcp);
    tcp_reassembly_direction_release_buffers(&flow->directions[FLOW_DIR_B_TO_A].tcp);
}

/*
 * Proactively reclaims flows whose TCP state is fully closed instead of
 * waiting for the idle timeout. Safe to call every time a new packet arrives;
 * closed flows are typically rare relative to total flow count.
 */
void flow_table_evict_closed(FlowTable *table) {
    size_t i = 0;

    if (table == NULL || table->flows == NULL) {
        return;
    }

    while (i < table->count) {
        if (flow_is_closed(&table->flows[i])) {
            bool rst = table->flows[i].directions[FLOW_DIR_A_TO_B].tcp.rst_seen ||
                      table->flows[i].directions[FLOW_DIR_B_TO_A].tcp.rst_seen;

            if (rst) {
                table->flows_closed_rst++;
            } else {
                table->flows_closed_fin++;
            }
            remove_flow_at(table, i);
        } else {
            i++;
        }
    }
}

/*
 * Combines already-evicted lifetime totals with the live counters of flows
 * still active in the table. Read-only: never mutates the table.
 */
FlowTableStats flow_table_snapshot_stats(const FlowTable *table) {
    FlowTableStats snapshot;
    size_t i;
    size_t active_directions = 0;

    memset(&snapshot, 0, sizeof(snapshot));
    if (table == NULL) {
        return snapshot;
    }

    snapshot.flows_created = table->flows_created;
    snapshot.flows_active = table->count;
    snapshot.flows_closed_fin = table->flows_closed_fin;
    snapshot.flows_closed_rst = table->flows_closed_rst;
    snapshot.flows_evicted_idle = table->flows_evicted_idle;
    snapshot.flows_evicted_capacity = table->flows_evicted_capacity;
    snapshot.retransmissions = table->retransmissions_total;
    snapshot.out_of_order_segments = table->out_of_order_segments_total;
    snapshot.overlapping_segments = table->overlapping_segments_total;
    snapshot.gaps = table->gaps_total;

    for (i = 0; i < table->count; i++) {
        const TcpReassemblyDirection *a_to_b = &table->flows[i].directions[FLOW_DIR_A_TO_B].tcp;
        const TcpReassemblyDirection *b_to_a = &table->flows[i].directions[FLOW_DIR_B_TO_A].tcp;

        snapshot.retransmissions += a_to_b->retransmissions + b_to_a->retransmissions;
        snapshot.out_of_order_segments +=
            a_to_b->out_of_order_segments + b_to_a->out_of_order_segments;
        snapshot.overlapping_segments += a_to_b->overlapping_segments + b_to_a->overlapping_segments;
        snapshot.gaps += a_to_b->gaps + b_to_a->gaps;
        if (a_to_b->stream.data != NULL) {
            active_directions++;
        }
        if (b_to_a->stream.data != NULL) {
            active_directions++;
        }
    }

    snapshot.stream_bytes_in_use = active_directions * table->stream_buffer_bytes;
    snapshot.stream_bytes_configured_max = table->max_flows * table->stream_buffer_bytes * 2;
    return snapshot;
}

/*
 * When the table is full after idle eviction, drop the least recently seen
 * flow to preserve the configured memory cap.
 */
static void evict_oldest_flow(FlowTable *table) {
    size_t i;
    size_t oldest_index = 0;

    if (table == NULL || table->count == 0) {
        return;
    }

    for (i = 1; i < table->count; i++) {
        if (table->flows[i].last_seen_time < table->flows[oldest_index].last_seen_time) {
            oldest_index = i;
        }
    }

    table->flows_evicted_capacity++;
    remove_flow_at(table, oldest_index);
}

/*
 * Lookup is the single creation boundary for the capture path. It performs
 * idle eviction first, then capacity eviction only if a new flow is needed.
 */
FlowInfo *flow_table_get_or_create(FlowTable *table, const PacketInfo *packet, uint64_t now_seconds,
                                   FlowDirection *direction) {
    FlowKey key;
    FlowDirection packet_direction;
    size_t i;
    FlowInfo *flow;

    if (table == NULL || table->flows == NULL || packet == NULL || packet->protocol != PROTO_TCP ||
        !flow_key_from_packet(packet, &key, &packet_direction)) {
        return NULL;
    }

    flow_table_evict_idle(table, now_seconds);
    flow_table_evict_closed(table);

    for (i = 0; i < table->count; i++) {
        if (flow_key_equals(&table->flows[i].key, &key)) {
            if (direction != NULL) {
                *direction = packet_direction;
            }
            return &table->flows[i];
        }
    }

    if (table->count >= table->max_flows) {
        evict_oldest_flow(table);
    }
    if (table->count >= table->max_flows) {
        return NULL;
    }

    flow = &table->flows[table->count];
    memset(flow, 0, sizeof(*flow));
    flow->key = key;
    flow->created_time = now_seconds;
    flow->last_seen_time = now_seconds;
    flow->stream_buffer_bytes = table->stream_buffer_bytes;
    /* Make unclassified flow state explicit for filters and output. */
    flow->app.protocol = APP_PROTO_UNKNOWN;
    table->count++;
    table->flows_created++;

    if (direction != NULL) {
        *direction = packet_direction;
    }
    return flow;
}

bool flow_prepare_reassembly_direction(FlowInfo *flow, FlowDirection direction) {
    TcpReassemblyDirection *tcp;

    if (flow == NULL || direction > FLOW_DIR_B_TO_A || flow->stream_buffer_bytes == 0) {
        return false;
    }

    tcp = &flow->directions[direction].tcp;
    if (tcp->stream.data != NULL) {
        return true;
    }

    return tcp_reassembly_direction_init(tcp, flow->stream_buffer_bytes);
}

/*
 * Counter updates stay separate from lookup so future reassembly can decide
 * exactly when a packet should advance per-direction stream state.
 */
void flow_update_packet(FlowInfo *flow, const PacketInfo *packet, uint64_t now_seconds,
                        FlowDirection direction) {
    if (flow == NULL || packet == NULL || direction > FLOW_DIR_B_TO_A) {
        return;
    }

    flow->last_seen_time = now_seconds;
    flow->packet_count++;
    flow->byte_count += packet->size;
    flow->directions[direction].packet_count++;
    flow->directions[direction].byte_count += packet->size;
}
