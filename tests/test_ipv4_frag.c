#include <assert.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipv4_frag.h"
#include "parser.h"
#include "stats.h"

static void make_fragment(PacketInfo *info, uint16_t id, const char *src_ip, const char *dst_ip,
                          size_t offset, int more, const unsigned char *payload,
                          size_t payload_length) {
    memset(info, 0, sizeof(*info));
    info->ip_version = 4;
    info->protocol = PROTO_TCP;
    info->is_ipv4_fragment = 1;
    info->ipv4_identification = id;
    info->ipv4_protocol_number = 6;
    info->ipv4_header_length = 20;
    info->ipv4_fragment_offset = offset;
    info->ipv4_more_fragments = more;
    info->ipv4_fragment_payload = payload;
    info->ipv4_fragment_payload_length = payload_length;
    snprintf(info->src_ip, sizeof(info->src_ip), "%s", src_ip);
    snprintf(info->dst_ip, sizeof(info->dst_ip), "%s", dst_ip);
    info->ipv4_header[0] = 0x45;
    info->ipv4_header[2] = 0;
    info->ipv4_header[3] = (unsigned char)(20 + payload_length);
    info->ipv4_header[4] = (unsigned char)(id >> 8);
    info->ipv4_header[5] = (unsigned char)id;
    info->ipv4_header[8] = 64;
    info->ipv4_header[9] = 6;
    info->ipv4_header[12] = 10;
    info->ipv4_header[15] = 1;
    info->ipv4_header[16] = 10;
    info->ipv4_header[19] = 2;
}

static void build_tcp_payload(unsigned char *payload, size_t payload_length) {
    memset(payload, 0, payload_length);
    payload[0] = 0xc3;
    payload[1] = 0x50;
    payload[3] = 80;
    payload[12] = 0x50;
    payload[13] = 0x18;
    memcpy(payload + 20, "GET /one", 8);
}

static void assert_assembled_tcp_packet(const IPv4FragmentProcessResult *result) {
    PacketInfo parsed;

    assert(result->result == IPV4_FRAGMENT_REASSEMBLED);
    assert(result->packet != NULL);
    assert(parser_parse_packet_with_datalink(result->packet, result->packet_length, DLT_RAW,
                                             &parsed) == 0);
    assert(parsed.protocol == PROTO_TCP);
    assert(parsed.has_ports == 1);
    assert(parsed.src_port == 50000);
    assert(parsed.dst_port == 80);
    assert(parsed.has_payload == 1);
    assert(parsed.payload_capture_length == 8);
    assert(memcmp(parsed.payload, "GET /one", 8) == 0);
}

static void test_ipv4_frag_reassembles_in_order(void) {
    IPv4FragmentTable table;
    PacketStats stats;
    unsigned char payload[28];
    PacketInfo first;
    PacketInfo second;
    IPv4FragmentProcessResult result;

    build_tcp_payload(payload, sizeof(payload));
    stats_init(&stats);
    assert(ipv4_fragment_table_init(&table, 4, 4096, 30));
    make_fragment(&first, 10, "10.0.0.1", "10.0.0.2", 0, 1, payload, 24);
    make_fragment(&second, 10, "10.0.0.1", "10.0.0.2", 24, 0, payload + 24, 4);

    result = ipv4_fragment_table_process(&table, &first, 1, &stats);
    assert(result.result == IPV4_FRAGMENT_QUEUED);
    result = ipv4_fragment_table_process(&table, &second, 2, &stats);
    assert_assembled_tcp_packet(&result);
    free(result.packet);

    assert(stats.ipv4_fragments_seen == 2);
    assert(stats.ipv4_fragments_reassembled == 1);
    ipv4_fragment_table_cleanup(&table);
}

static void test_ipv4_frag_reassembles_out_of_order(void) {
    IPv4FragmentTable table;
    PacketStats stats;
    unsigned char payload[28];
    PacketInfo first;
    PacketInfo second;
    IPv4FragmentProcessResult result;

    build_tcp_payload(payload, sizeof(payload));
    stats_init(&stats);
    assert(ipv4_fragment_table_init(&table, 4, 4096, 30));
    make_fragment(&first, 11, "10.0.0.1", "10.0.0.2", 0, 1, payload, 24);
    make_fragment(&second, 11, "10.0.0.1", "10.0.0.2", 24, 0, payload + 24, 4);

    result = ipv4_fragment_table_process(&table, &second, 1, &stats);
    assert(result.result == IPV4_FRAGMENT_QUEUED);
    result = ipv4_fragment_table_process(&table, &first, 2, &stats);
    assert_assembled_tcp_packet(&result);
    free(result.packet);
    ipv4_fragment_table_cleanup(&table);
}

static void test_ipv4_frag_rejects_overlap(void) {
    IPv4FragmentTable table;
    PacketStats stats;
    unsigned char payload[32];
    PacketInfo first;
    PacketInfo overlap;
    IPv4FragmentProcessResult result;

    memset(payload, 'A', sizeof(payload));
    stats_init(&stats);
    assert(ipv4_fragment_table_init(&table, 4, 4096, 30));
    make_fragment(&first, 12, "10.0.0.1", "10.0.0.2", 0, 1, payload, 16);
    make_fragment(&overlap, 12, "10.0.0.1", "10.0.0.2", 8, 0, payload + 8, 16);

    result = ipv4_fragment_table_process(&table, &first, 1, &stats);
    assert(result.result == IPV4_FRAGMENT_QUEUED);
    result = ipv4_fragment_table_process(&table, &overlap, 2, &stats);
    assert(result.result == IPV4_FRAGMENT_MALFORMED);
    assert(stats.ipv4_fragments_malformed == 1);
    assert(table.count == 0);
    ipv4_fragment_table_cleanup(&table);
}

static void test_ipv4_frag_expires_idle_datagrams(void) {
    IPv4FragmentTable table;
    PacketStats stats;
    unsigned char payload[16];
    PacketInfo first;
    PacketInfo second;

    memset(payload, 'A', sizeof(payload));
    stats_init(&stats);
    assert(ipv4_fragment_table_init(&table, 4, 4096, 5));
    make_fragment(&first, 13, "10.0.0.1", "10.0.0.2", 0, 1, payload, 16);
    make_fragment(&second, 14, "10.0.0.3", "10.0.0.4", 0, 1, payload, 16);

    assert(ipv4_fragment_table_process(&table, &first, 1, &stats).result == IPV4_FRAGMENT_QUEUED);
    assert(ipv4_fragment_table_process(&table, &second, 7, &stats).result == IPV4_FRAGMENT_QUEUED);
    assert(stats.ipv4_fragments_expired == 1);
    assert(table.count == 1);
    ipv4_fragment_table_cleanup(&table);
}

static void test_ipv4_frag_rejects_malformed_fragment(void) {
    IPv4FragmentTable table;
    PacketStats stats;
    unsigned char payload[10];
    PacketInfo malformed;
    IPv4FragmentProcessResult result;

    memset(payload, 'A', sizeof(payload));
    stats_init(&stats);
    assert(ipv4_fragment_table_init(&table, 4, 4096, 30));
    make_fragment(&malformed, 15, "10.0.0.1", "10.0.0.2", 0, 1, payload, sizeof(payload));

    result = ipv4_fragment_table_process(&table, &malformed, 1, &stats);
    assert(result.result == IPV4_FRAGMENT_MALFORMED);
    assert(stats.ipv4_fragments_malformed == 1);
    assert(table.count == 0);
    ipv4_fragment_table_cleanup(&table);
}

static void test_ipv4_frag_drops_when_caps_are_exhausted(void) {
    IPv4FragmentTable table;
    PacketStats stats;
    unsigned char payload[16];
    PacketInfo first;
    PacketInfo second;

    memset(payload, 'A', sizeof(payload));
    stats_init(&stats);
    assert(ipv4_fragment_table_init(&table, 1, 4096, 30));
    make_fragment(&first, 16, "10.0.0.1", "10.0.0.2", 0, 1, payload, 16);
    make_fragment(&second, 17, "10.0.0.3", "10.0.0.4", 0, 1, payload, 16);

    assert(ipv4_fragment_table_process(&table, &first, 1, &stats).result == IPV4_FRAGMENT_QUEUED);
    assert(ipv4_fragment_table_process(&table, &second, 2, &stats).result == IPV4_FRAGMENT_DROPPED);
    assert(stats.ipv4_fragments_dropped == 1);
    ipv4_fragment_table_cleanup(&table);

    stats_init(&stats);
    assert(ipv4_fragment_table_init(&table, 4, 8, 30));
    assert(ipv4_fragment_table_process(&table, &first, 1, &stats).result == IPV4_FRAGMENT_DROPPED);
    assert(stats.ipv4_fragments_dropped == 1);
    ipv4_fragment_table_cleanup(&table);
}

static void test_ipv4_frag_rejects_invalid_init_and_inputs(void) {
    IPv4FragmentTable table;
    PacketStats stats;
    PacketInfo packet;

    stats_init(&stats);
    memset(&packet, 0, sizeof(packet));
    assert(!ipv4_fragment_table_init(NULL, 1, 1024, 30));
    assert(!ipv4_fragment_table_init(&table, 0, 1024, 30));
    assert(!ipv4_fragment_table_init(&table, 1, 0, 30));
    assert(
        !ipv4_fragment_table_init(&table, MINISNIFFER_MAX_IPV4_FRAGMENT_DATAGRAMS + 1, 1024, 30));
    assert(!ipv4_fragment_table_init(&table, 1, MINISNIFFER_MAX_IPV4_FRAGMENT_BYTES + 1, 30));

    assert(ipv4_fragment_table_process(NULL, &packet, 1, &stats).result == IPV4_FRAGMENT_IGNORED);
    assert(ipv4_fragment_table_init(&table, 1, 1024, 0));
    assert(ipv4_fragment_table_process(&table, NULL, 1, &stats).result == IPV4_FRAGMENT_IGNORED);
    assert(ipv4_fragment_table_process(&table, &packet, 1, &stats).result == IPV4_FRAGMENT_IGNORED);
    ipv4_fragment_table_expire(NULL, 1, &stats);
    ipv4_fragment_table_cleanup(NULL);
    ipv4_fragment_table_cleanup(&table);
}

int main(void) {
    test_ipv4_frag_reassembles_in_order();
    test_ipv4_frag_reassembles_out_of_order();
    test_ipv4_frag_rejects_overlap();
    test_ipv4_frag_expires_idle_datagrams();
    test_ipv4_frag_rejects_malformed_fragment();
    test_ipv4_frag_drops_when_caps_are_exhausted();
    test_ipv4_frag_rejects_invalid_init_and_inputs();

    printf("All IPv4 fragment tests passed.\n");
    return 0;
}
