#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "flow.h"

static PacketInfo make_tcp_packet(const char *src_ip, uint16_t src_port, const char *dst_ip,
                                  uint16_t dst_port, size_t size) {
    PacketInfo packet;

    memset(&packet, 0, sizeof(packet));
    snprintf(packet.src_ip, sizeof(packet.src_ip), "%s", src_ip);
    snprintf(packet.dst_ip, sizeof(packet.dst_ip), "%s", dst_ip);
    packet.src_port = src_port;
    packet.dst_port = dst_port;
    packet.has_ports = 1;
    packet.protocol = PROTO_TCP;
    packet.size = size;

    return packet;
}

static int ip_address_equals(IPAddress left, IPAddress right) {
    return left.family == right.family && memcmp(left.bytes, right.bytes, sizeof(left.bytes)) == 0;
}

static void test_flow_key_normalizes_tcp_directions(void) {
    PacketInfo forward = make_tcp_packet("10.0.0.1", 50000, "93.184.216.34", 80, 100);
    PacketInfo reverse = make_tcp_packet("93.184.216.34", 80, "10.0.0.1", 50000, 120);
    FlowKey forward_key;
    FlowKey reverse_key;
    FlowDirection forward_direction;
    FlowDirection reverse_direction;

    assert(flow_key_from_packet(&forward, &forward_key, &forward_direction));
    assert(flow_key_from_packet(&reverse, &reverse_key, &reverse_direction));

    assert(ip_address_equals(forward_key.a_ip, reverse_key.a_ip));
    assert(forward_key.a_port == reverse_key.a_port);
    assert(ip_address_equals(forward_key.b_ip, reverse_key.b_ip));
    assert(forward_key.b_port == reverse_key.b_port);
    assert(forward_key.transport_protocol == 6);
    assert(forward_direction == FLOW_DIR_A_TO_B);
    assert(reverse_direction == FLOW_DIR_B_TO_A);
}

static void test_flow_table_create_find_and_update(void) {
    FlowTable table;
    PacketInfo forward = make_tcp_packet("10.0.0.1", 50000, "93.184.216.34", 80, 100);
    PacketInfo reverse = make_tcp_packet("93.184.216.34", 80, "10.0.0.1", 50000, 120);
    FlowDirection direction;
    FlowInfo *first;
    FlowInfo *second;

    assert(flow_table_init(&table, 4, 1024, 60));

    first = flow_table_get_or_create(&table, &forward, 10, &direction);
    assert(first != NULL);
    assert(first->directions[FLOW_DIR_A_TO_B].tcp.stream.data == NULL);
    assert(first->directions[FLOW_DIR_B_TO_A].tcp.stream.data == NULL);
    assert(flow_prepare_reassembly_direction(first, direction));
    assert(first->directions[FLOW_DIR_A_TO_B].tcp.stream.data != NULL);
    assert(first->directions[FLOW_DIR_B_TO_A].tcp.stream.data == NULL);
    assert(direction == FLOW_DIR_A_TO_B);
    flow_update_packet(first, &forward, 10, direction);

    second = flow_table_get_or_create(&table, &reverse, 12, &direction);
    assert(second == first);
    assert(direction == FLOW_DIR_B_TO_A);
    flow_update_packet(second, &reverse, 12, direction);

    assert(table.count == 1);
    assert(first->created_time == 10);
    assert(first->last_seen_time == 12);
    assert(first->packet_count == 2);
    assert(first->byte_count == 220);
    assert(first->directions[FLOW_DIR_A_TO_B].packet_count == 1);
    assert(first->directions[FLOW_DIR_B_TO_A].packet_count == 1);

    flow_table_cleanup(&table);
    assert(table.flows == NULL);
    assert(table.count == 0);
}

static void test_flow_table_evicts_idle_flows(void) {
    FlowTable table;
    PacketInfo first_packet = make_tcp_packet("10.0.0.1", 50000, "93.184.216.34", 80, 100);
    PacketInfo second_packet = make_tcp_packet("10.0.0.2", 50001, "93.184.216.34", 80, 100);
    FlowDirection direction;

    assert(flow_table_init(&table, 4, 1024, 10));
    assert(flow_table_get_or_create(&table, &first_packet, 10, &direction) != NULL);
    assert(flow_table_get_or_create(&table, &second_packet, 25, &direction) != NULL);
    assert(table.count == 1);

    flow_table_cleanup(&table);
}

static void test_flow_table_caps_max_flows(void) {
    FlowTable table;
    PacketInfo first_packet = make_tcp_packet("10.0.0.1", 50000, "93.184.216.34", 80, 100);
    PacketInfo second_packet = make_tcp_packet("10.0.0.2", 50001, "93.184.216.34", 80, 100);
    FlowDirection direction;

    assert(flow_table_init(&table, 1, 1024, 60));
    assert(flow_table_get_or_create(&table, &first_packet, 10, &direction) != NULL);
    assert(table.count == 1);
    assert(flow_table_get_or_create(&table, &second_packet, 11, &direction) != NULL);
    assert(table.count == 1);

    flow_table_cleanup(&table);
}

static int flow_matches_packet(const FlowInfo *flow, const PacketInfo *packet) {
    FlowKey key;

    return flow != NULL && flow_key_from_packet(packet, &key, NULL) &&
           ip_address_equals(flow->key.a_ip, key.a_ip) && flow->key.a_port == key.a_port &&
           ip_address_equals(flow->key.b_ip, key.b_ip) && flow->key.b_port == key.b_port &&
           flow->key.transport_protocol == key.transport_protocol;
}

static void test_flow_table_evicts_oldest_flow_when_full(void) {
    FlowTable table;
    PacketInfo first_packet = make_tcp_packet("10.0.0.1", 50000, "93.184.216.34", 80, 100);
    PacketInfo second_packet = make_tcp_packet("10.0.0.2", 50001, "93.184.216.34", 80, 100);
    PacketInfo third_packet = make_tcp_packet("10.0.0.3", 50002, "93.184.216.34", 80, 100);
    FlowDirection direction;
    size_t i;
    int saw_first = 0;
    int saw_second = 0;
    int saw_third = 0;

    assert(flow_table_init(&table, 2, 1024, 60));
    assert(flow_table_get_or_create(&table, &first_packet, 10, &direction) != NULL);
    assert(flow_table_get_or_create(&table, &second_packet, 20, &direction) != NULL);
    assert(flow_table_get_or_create(&table, &third_packet, 30, &direction) != NULL);
    assert(table.count == 2);

    for (i = 0; i < table.count; i++) {
        saw_first = saw_first || flow_matches_packet(&table.flows[i], &first_packet);
        saw_second = saw_second || flow_matches_packet(&table.flows[i], &second_packet);
        saw_third = saw_third || flow_matches_packet(&table.flows[i], &third_packet);
    }

    assert(!saw_first);
    assert(saw_second);
    assert(saw_third);

    flow_table_cleanup(&table);
}

static void test_flow_key_rejects_packets_without_ports(void) {
    PacketInfo packet;
    FlowKey key;

    memset(&packet, 0, sizeof(packet));
    packet.protocol = PROTO_ICMP;
    snprintf(packet.src_ip, sizeof(packet.src_ip), "10.0.0.1");
    snprintf(packet.dst_ip, sizeof(packet.dst_ip), "10.0.0.2");

    assert(!flow_key_from_packet(&packet, &key, NULL));
}

static void test_flow_table_rejects_unsafe_limits(void) {
    FlowTable table;

    assert(!flow_table_init(NULL, 1, 1024, 60));
    assert(!flow_table_init(&table, 0, 1024, 60));
    assert(!flow_table_init(&table, 1, 0, 60));
    assert(!flow_table_init(&table, MINISNIFFER_MAX_FLOWS + 1, 1024, 60));
    assert(!flow_table_init(&table, 1, MINISNIFFER_MAX_STREAM_BUFFER_BYTES + 1, 60));
    assert(!flow_table_init(&table, 1024, 32769, 60));
}

static void test_flow_key_supports_udp_and_endpoint_ties(void) {
    PacketInfo packet = make_tcp_packet("10.0.0.1", 60000, "10.0.0.1", 50000, 10);
    FlowKey key;
    FlowDirection direction;

    assert(flow_key_from_packet(&packet, &key, &direction));
    assert(direction == FLOW_DIR_B_TO_A);

    packet.src_port = 50000;
    packet.dst_port = 60000;
    assert(flow_key_from_packet(&packet, &key, &direction));
    assert(direction == FLOW_DIR_A_TO_B);

    packet.src_port = 50000;
    packet.dst_port = 50000;
    assert(flow_key_from_packet(&packet, &key, &direction));
    assert(direction == FLOW_DIR_A_TO_B);

    packet.protocol = PROTO_UDP;
    packet.src_port = 60000;
    packet.dst_port = 50000;
    assert(flow_key_from_packet(&packet, &key, &direction));
    assert(key.transport_protocol == 17);
    assert(key.a_port == 60000);
    assert(direction == FLOW_DIR_A_TO_B);
}

static void test_flow_key_supports_ipv6_tcp_reassembly(void) {
    FlowTable table;
    PacketInfo forward = make_tcp_packet("2001:db8::2", 50000, "2001:db8::1", 443, 100);
    PacketInfo reverse = make_tcp_packet("2001:db8::1", 443, "2001:db8::2", 50000, 120);
    FlowDirection direction;
    FlowInfo *first;
    FlowInfo *second;

    assert(flow_table_init(&table, 2, 1024, 60));
    first = flow_table_get_or_create(&table, &forward, 1, &direction);
    assert(first != NULL);
    assert(direction == FLOW_DIR_B_TO_A);
    second = flow_table_get_or_create(&table, &reverse, 2, &direction);
    assert(second == first);
    assert(direction == FLOW_DIR_A_TO_B);
    assert(table.count == 1);
    flow_table_cleanup(&table);
}

static void test_flow_functions_reject_invalid_inputs(void) {
    FlowTable table;
    FlowInfo flow;
    FlowKey key;
    PacketInfo packet = make_tcp_packet("bad-ip", 1, "10.0.0.2", 2, 10);

    memset(&table, 0, sizeof(table));
    memset(&flow, 0, sizeof(flow));
    flow_table_cleanup(NULL);
    flow_table_cleanup(&table);
    flow_table_evict_idle(NULL, 10);
    flow_table_evict_idle(&table, 10);

    assert(!flow_key_from_packet(NULL, &key, NULL));
    assert(!flow_key_from_packet(&packet, NULL, NULL));
    assert(!flow_key_from_packet(&packet, &key, NULL));
    snprintf(packet.src_ip, sizeof(packet.src_ip), "10.0.0.1");
    packet.protocol = PROTO_OTHER;
    assert(!flow_key_from_packet(&packet, &key, NULL));

    assert(flow_table_get_or_create(NULL, &packet, 1, NULL) == NULL);
    assert(flow_table_get_or_create(&table, &packet, 1, NULL) == NULL);
    assert(flow_table_get_or_create(&table, NULL, 1, NULL) == NULL);

    assert(!flow_prepare_reassembly_direction(NULL, FLOW_DIR_A_TO_B));
    assert(!flow_prepare_reassembly_direction(&flow, (FlowDirection)2));
    assert(!flow_prepare_reassembly_direction(&flow, FLOW_DIR_A_TO_B));

    flow_update_packet(NULL, &packet, 1, FLOW_DIR_A_TO_B);
    flow_update_packet(&flow, NULL, 1, FLOW_DIR_A_TO_B);
    flow_update_packet(&flow, &packet, 1, (FlowDirection)2);
}

static void test_flow_table_handles_zero_timeout_and_clock_rollback(void) {
    FlowTable table;
    PacketInfo packet = make_tcp_packet("10.0.0.1", 50000, "10.0.0.2", 80, 10);
    FlowDirection direction;

    assert(flow_table_init(&table, 2, 64, 0));
    assert(flow_table_get_or_create(&table, &packet, 20, &direction) != NULL);
    flow_table_evict_idle(&table, 10);
    assert(table.count == 1);
    flow_table_cleanup(&table);

    assert(flow_table_init(&table, 2, 64, 5));
    assert(flow_table_get_or_create(&table, &packet, 20, &direction) != NULL);
    flow_table_evict_idle(&table, 10);
    assert(table.count == 1);
    flow_table_cleanup(&table);
}

static void test_flow_table_can_select_nonzero_oldest_index(void) {
    FlowTable table;
    PacketInfo first = make_tcp_packet("10.0.0.1", 50000, "10.0.0.9", 80, 10);
    PacketInfo second = make_tcp_packet("10.0.0.2", 50001, "10.0.0.9", 80, 10);
    PacketInfo third = make_tcp_packet("10.0.0.3", 50002, "10.0.0.9", 80, 10);
    FlowDirection direction;

    assert(flow_table_init(&table, 2, 64, 0));
    assert(flow_table_get_or_create(&table, &first, 20, &direction) != NULL);
    assert(flow_table_get_or_create(&table, &second, 10, &direction) != NULL);
    assert(flow_table_get_or_create(&table, &third, 30, &direction) != NULL);
    assert(table.count == 2);
    assert(flow_matches_packet(&table.flows[0], &first));
    assert(flow_matches_packet(&table.flows[1], &third));
    flow_table_cleanup(&table);
}

static void test_flow_table_rejects_manually_exhausted_table(void) {
    FlowInfo storage;
    FlowTable table;
    PacketInfo packet = make_tcp_packet("10.0.0.1", 50000, "10.0.0.2", 80, 10);

    memset(&storage, 0, sizeof(storage));
    memset(&table, 0, sizeof(table));
    table.flows = &storage;
    table.max_flows = 0;
    assert(flow_table_get_or_create(&table, &packet, 1, NULL) == NULL);
}

int main(void) {
    test_flow_key_normalizes_tcp_directions();
    test_flow_table_create_find_and_update();
    test_flow_table_evicts_idle_flows();
    test_flow_table_caps_max_flows();
    test_flow_table_evicts_oldest_flow_when_full();
    test_flow_key_rejects_packets_without_ports();
    test_flow_table_rejects_unsafe_limits();
    test_flow_key_supports_udp_and_endpoint_ties();
    test_flow_key_supports_ipv6_tcp_reassembly();
    test_flow_functions_reject_invalid_inputs();
    test_flow_table_handles_zero_timeout_and_clock_rollback();
    test_flow_table_can_select_nonzero_oldest_index();
    test_flow_table_rejects_manually_exhausted_table();

    printf("All flow tests passed.\n");

    return 0;
}
