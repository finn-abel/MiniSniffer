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
    stats.other_packets = 99;
    stats.total_bytes = 99;

    stats_init(&stats);

    assert(stats.total_packets == 0);
    assert(stats.tcp_packets == 0);
    assert(stats.udp_packets == 0);
    assert(stats.icmp_packets == 0);
    assert(stats.other_packets == 0);
    assert(stats.total_bytes == 0);
}

static void test_stats_update_tracks_protocol_counts_and_bytes(void) {
    PacketStats stats;
    PacketInfo tcp = make_packet(PROTO_TCP, 100);
    PacketInfo udp = make_packet(PROTO_UDP, 200);
    PacketInfo icmp = make_packet(PROTO_ICMP, 300);
    PacketInfo other = make_packet(PROTO_OTHER, 400);

    stats_init(&stats);
    stats_update(&stats, &tcp);
    stats_update(&stats, &udp);
    stats_update(&stats, &icmp);
    stats_update(&stats, &other);

    assert(stats.total_packets == 4);
    assert(stats.tcp_packets == 1);
    assert(stats.udp_packets == 1);
    assert(stats.icmp_packets == 1);
    assert(stats.other_packets == 1);
    assert(stats.total_bytes == 1000);
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
    test_stats_functions_accept_null_inputs();
    test_stats_print_handles_empty_and_populated_stats();

    printf("All stats tests passed.\n");

    return 0;
}
