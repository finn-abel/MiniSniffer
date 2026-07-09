#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "stats.h"

static PacketInfo make_packet(Protocol protocol, size_t size) {
    PacketInfo info;

    memset(&info, 0, sizeof(info));
    info.protocol = protocol;
    info.size = size;

    return info;
}

static void test_stats_init_clears_counters(void) {
    PacketStats stats;

    stats.total_packets = 99;
    stats.tcp_packets = 99;
    stats.udp_packets = 99;
    stats.icmp_packets = 99;
    stats.arp_packets = 99;
    stats.other_packets = 99;
    stats.total_bytes = 99;
    stats.ipv4_fragments_seen = 99;
    stats.ipv4_fragments_reassembled = 99;
    stats.ipv4_fragments_expired = 99;
    stats.ipv4_fragments_malformed = 99;
    stats.ipv4_fragments_dropped = 99;
    stats.app_decode_no_match = 99;
    stats.app_decode_need_more = 99;
    stats.app_decode_malformed = 99;
    stats.app_decode_truncated = 99;
    stats.app_decode_decoded = 99;
    stats.flow_count_created = 99;
    stats.flow_count_active_at_exit = 99;
    stats.flow_closed_fin = 99;
    stats.flow_closed_rst = 99;
    stats.flow_evicted_idle = 99;
    stats.flow_evicted_capacity = 99;
    stats.flow_retransmissions = 99;
    stats.flow_out_of_order_segments = 99;
    stats.flow_overlapping_segments = 99;
    stats.flow_gaps = 99;
    stats.flow_stream_bytes_in_use = 99;
    stats.flow_stream_bytes_configured_max = 99;

    stats_init(&stats);

    assert(stats.total_packets == 0);
    assert(stats.tcp_packets == 0);
    assert(stats.udp_packets == 0);
    assert(stats.icmp_packets == 0);
    assert(stats.arp_packets == 0);
    assert(stats.other_packets == 0);
    assert(stats.total_bytes == 0);
    assert(stats.ipv4_fragments_seen == 0);
    assert(stats.ipv4_fragments_reassembled == 0);
    assert(stats.ipv4_fragments_expired == 0);
    assert(stats.ipv4_fragments_malformed == 0);
    assert(stats.ipv4_fragments_dropped == 0);
    assert(stats.app_decode_no_match == 0);
    assert(stats.app_decode_need_more == 0);
    assert(stats.app_decode_malformed == 0);
    assert(stats.app_decode_truncated == 0);
    assert(stats.app_decode_decoded == 0);
    assert(stats.flow_count_created == 0);
    assert(stats.flow_count_active_at_exit == 0);
    assert(stats.flow_closed_fin == 0);
    assert(stats.flow_closed_rst == 0);
    assert(stats.flow_evicted_idle == 0);
    assert(stats.flow_evicted_capacity == 0);
    assert(stats.flow_retransmissions == 0);
    assert(stats.flow_out_of_order_segments == 0);
    assert(stats.flow_overlapping_segments == 0);
    assert(stats.flow_gaps == 0);
    assert(stats.flow_stream_bytes_in_use == 0);
    assert(stats.flow_stream_bytes_configured_max == 0);
}

static void test_stats_update_tracks_protocol_counts_and_bytes(void) {
    PacketStats stats;
    PacketInfo tcp = make_packet(PROTO_TCP, 100);
    PacketInfo udp = make_packet(PROTO_UDP, 200);
    PacketInfo icmp = make_packet(PROTO_ICMP, 300);
    PacketInfo arp = make_packet(PROTO_ARP, 50);
    PacketInfo other = make_packet(PROTO_OTHER, 400);

    tcp.app_decode_status = APP_DECODE_STATUS_DECODED;
    udp.app_decode_status = APP_DECODE_STATUS_NO_MATCH;
    icmp.app_decode_status = APP_DECODE_STATUS_NEED_MORE;
    other.app_decode_status = APP_DECODE_STATUS_TRUNCATED;
    stats_init(&stats);
    stats_update(&stats, &tcp);
    stats_update(&stats, &udp);
    stats_update(&stats, &icmp);
    stats_update(&stats, &arp);
    stats_update(&stats, &other);

    assert(stats.total_packets == 5);
    assert(stats.tcp_packets == 1);
    assert(stats.udp_packets == 1);
    assert(stats.icmp_packets == 1);
    assert(stats.arp_packets == 1);
    assert(stats.other_packets == 1);
    assert(stats.total_bytes == 1050);
    assert(stats.app_decode_decoded == 1);
    assert(stats.app_decode_no_match == 1);
    assert(stats.app_decode_need_more == 1);
    assert(stats.app_decode_truncated == 1);
}

static PacketInfo make_tcp_flow_packet(const char *src_ip, uint16_t src_port, const char *dst_ip,
                                       uint16_t dst_port) {
    PacketInfo packet;

    memset(&packet, 0, sizeof(packet));
    snprintf(packet.src_ip, sizeof(packet.src_ip), "%s", src_ip);
    snprintf(packet.dst_ip, sizeof(packet.dst_ip), "%s", dst_ip);
    packet.src_port = src_port;
    packet.dst_port = dst_port;
    packet.has_ports = 1;
    packet.protocol = PROTO_TCP;
    return packet;
}

static void test_stats_apply_flow_table_copies_snapshot(void) {
    FlowTable table;
    PacketStats stats;
    PacketInfo packet = make_tcp_flow_packet("10.0.0.1", 50000, "10.0.0.2", 80);
    FlowDirection direction;

    assert(flow_table_init(&table, 4, 128, 60));
    assert(flow_table_get_or_create(&table, &packet, 1, &direction) != NULL);

    stats_init(&stats);
    stats_apply_flow_table(&stats, &table);
    assert(stats.flow_count_created == 1);
    assert(stats.flow_count_active_at_exit == 1);

    stats_apply_flow_table(NULL, &table);
    stats_apply_flow_table(&stats, NULL);
    assert(stats.flow_count_created == 1);

    flow_table_cleanup(&table);
}

static void test_stats_functions_accept_null_inputs(void) {
    PacketStats stats;
    PacketInfo packet = make_packet(PROTO_TCP, 100);

    stats_init(&stats);

    stats_init(NULL);
    stats_update(NULL, &packet);
    stats_update(&stats, NULL);
    stats_print(NULL);

    assert(stats.total_packets == 0);
}

static void test_stats_print_handles_empty_and_populated_stats(void) {
    PacketStats stats;
    PacketInfo packet = make_packet(PROTO_TCP, 101);

    stats_init(&stats);
    stats_print(&stats);
    stats_update(&stats, &packet);
    stats_print(&stats);
}

int main(void) {
    test_stats_init_clears_counters();
    test_stats_update_tracks_protocol_counts_and_bytes();
    test_stats_apply_flow_table_copies_snapshot();
    test_stats_functions_accept_null_inputs();
    test_stats_print_handles_empty_and_populated_stats();

    printf("All stats tests passed.\n");

    return 0;
}
