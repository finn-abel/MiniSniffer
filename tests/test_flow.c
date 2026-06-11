#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "flow.h"

static PacketInfo make_tcp_packet(
    const char *src_ip,
    uint16_t src_port,
    const char *dst_ip,
    uint16_t dst_port,
    size_t size
) {
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

static void test_flow_key_normalizes_tcp_directions(void) {
    PacketInfo forward = make_tcp_packet("10.0.0.1", 50000, "93.184.216.34", 80, 100);
    PacketInfo reverse = make_tcp_packet("93.184.216.34", 80, "10.0.0.1", 50000, 120);
    FlowKey forward_key;
    FlowKey reverse_key;
    FlowDirection forward_direction;
    FlowDirection reverse_direction;

    assert(flow_key_from_packet(&forward, &forward_key, &forward_direction));
    assert(flow_key_from_packet(&reverse, &reverse_key, &reverse_direction));

    assert(forward_key.a_ip.ipv4 == reverse_key.a_ip.ipv4);
    assert(forward_key.a_port == reverse_key.a_port);
    assert(forward_key.b_ip.ipv4 == reverse_key.b_ip.ipv4);
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

    return flow != NULL &&
           flow_key_from_packet(packet, &key, NULL) &&
           flow->key.a_ip.ipv4 == key.a_ip.ipv4 &&
           flow->key.a_port == key.a_port &&
           flow->key.b_ip.ipv4 == key.b_ip.ipv4 &&
           flow->key.b_port == key.b_port &&
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

int main(void) {
    test_flow_key_normalizes_tcp_directions();
    test_flow_table_create_find_and_update();
    test_flow_table_evicts_idle_flows();
    test_flow_table_caps_max_flows();
    test_flow_table_evicts_oldest_flow_when_full();
    test_flow_key_rejects_packets_without_ports();

    printf("All flow tests passed.\n");

    return 0;
}
