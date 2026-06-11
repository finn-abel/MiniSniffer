#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_decoder.h"
#include "flow.h"
#include "fixtures/app_fixtures.h"

static PacketInfo make_tcp_packet(uint16_t src_port, uint16_t dst_port) {
    PacketInfo packet;

    memset(&packet, 0, sizeof(packet));
    snprintf(packet.src_ip, sizeof(packet.src_ip), "192.168.1.25");
    snprintf(packet.dst_ip, sizeof(packet.dst_ip), "93.184.216.34");
    packet.protocol = PROTO_TCP;
    packet.has_ports = 1;
    packet.src_port = src_port;
    packet.dst_port = dst_port;
    packet.has_tcp_sequence = 1;
    return packet;
}

static FlowInfo *make_flow(FlowTable *table, PacketInfo *packet, FlowDirection *direction) {
    FlowInfo *flow;

    assert(flow_table_init(table, 4, 65536, 60));
    flow = flow_table_get_or_create(table, packet, 10, direction);
    assert(flow != NULL);
    return flow;
}

static AppDecodeResult feed_segment(
    FlowInfo *flow,
    FlowDirection direction,
    PacketInfo *packet,
    uint32_t sequence,
    const uint8_t *data,
    size_t length
) {
    TcpReassemblyDirection *tcp = &flow->directions[direction].tcp;
    AppDecodeResult result;

    packet->tcp_sequence = sequence;
    packet->tcp_flags = 0;
    packet->payload = data;
    packet->payload_decode_length = length;
    packet->payload_capture_length = length;
    packet->has_payload = length > 0;

    assert(tcp_reassembly_process_segment(tcp,
                                          packet->tcp_sequence,
                                          packet->tcp_flags,
                                          packet->payload,
                                          packet->payload_decode_length) != TCP_REASSEMBLY_DROPPED);
    result = app_decode_stream(packet,
                               stream_buffer_data(&tcp->stream),
                               stream_buffer_length(&tcp->stream),
                               &flow->app);
    if (result == APP_DECODE_OK && flow->app.protocol != APP_PROTO_UNKNOWN) {
        flow->app_classified = true;
    }
    return result;
}

static void test_http_request_split_across_two_tcp_segments(void) {
    FlowTable table;
    PacketInfo packet = make_tcp_packet(50000, 80);
    FlowDirection direction;
    FlowInfo *flow = make_flow(&table, &packet, &direction);
    const uint8_t first[] = "GET /index.html HTTP/1.1\r\n";
    const uint8_t second[] = "Host: example.com\r\n\r\n";

    assert(feed_segment(flow, direction, &packet, 100, first, sizeof(first) - 1) ==
           APP_DECODE_NEED_MORE);
    assert(!flow->app_classified);
    assert(feed_segment(flow, direction, &packet, 100 + sizeof(first) - 1, second, sizeof(second) - 1) ==
           APP_DECODE_OK);
    assert(flow->app_classified);
    assert(flow->app.protocol == APP_PROTO_HTTP);
    assert(strcmp(flow->app.http_host, "example.com") == 0);
    flow_table_cleanup(&table);
}

static void test_http_headers_split_across_multiple_packets(void) {
    FlowTable table;
    PacketInfo packet = make_tcp_packet(50000, 80);
    FlowDirection direction;
    FlowInfo *flow = make_flow(&table, &packet, &direction);
    const uint8_t a[] = "GET / HTTP/1.1\r\n";
    const uint8_t b[] = "Host: example";
    const uint8_t c[] = ".com\r\nUser-Agent: test\r\n\r\n";

    assert(feed_segment(flow, direction, &packet, 1, a, sizeof(a) - 1) == APP_DECODE_NEED_MORE);
    assert(feed_segment(flow, direction, &packet, 1 + sizeof(a) - 1, b, sizeof(b) - 1) ==
           APP_DECODE_NEED_MORE);
    assert(feed_segment(flow,
                        direction,
                        &packet,
                        1 + sizeof(a) - 1 + sizeof(b) - 1,
                        c,
                        sizeof(c) - 1) == APP_DECODE_OK);
    assert(strcmp(flow->app.http_host, "example.com") == 0);
    flow_table_cleanup(&table);
}

static void test_tls_client_hello_split_across_two_segments(void) {
    FlowTable table;
    PacketInfo packet = make_tcp_packet(50000, 443);
    FlowDirection direction;
    FlowInfo *flow = make_flow(&table, &packet, &direction);
    size_t split = 20;

    assert(feed_segment(flow, direction, &packet, 50, TLS_CLIENT_HELLO_SNI_ALPN, split) ==
           APP_DECODE_NEED_MORE);
    assert(feed_segment(flow,
                        direction,
                        &packet,
                        50 + (uint32_t)split,
                        TLS_CLIENT_HELLO_SNI_ALPN + split,
                        sizeof(TLS_CLIENT_HELLO_SNI_ALPN) - split) == APP_DECODE_OK);
    assert(flow->app.protocol == APP_PROTO_TLS);
    assert(strcmp(flow->app.tls_sni, "example.com") == 0);
    assert(strcmp(flow->app.tls_alpn, "h2,http/1.1") == 0);
    flow_table_cleanup(&table);
}

static void test_dns_over_tcp_split_across_two_segments(void) {
    FlowTable table;
    PacketInfo packet = make_tcp_packet(50000, 53);
    FlowDirection direction;
    FlowInfo *flow = make_flow(&table, &packet, &direction);
    uint8_t frame[2 + sizeof(DNS_A_QUERY)];
    size_t first_len = 8;

    frame[0] = (uint8_t)(sizeof(DNS_A_QUERY) >> 8);
    frame[1] = (uint8_t)(sizeof(DNS_A_QUERY) & 0xff);
    memcpy(frame + 2, DNS_A_QUERY, sizeof(DNS_A_QUERY));

    assert(feed_segment(flow, direction, &packet, 10, frame, first_len) == APP_DECODE_NEED_MORE);
    assert(feed_segment(flow,
                        direction,
                        &packet,
                        10 + (uint32_t)first_len,
                        frame + first_len,
                        sizeof(frame) - first_len) == APP_DECODE_OK);
    assert(flow->app.protocol == APP_PROTO_DNS);
    assert(strcmp(flow->app.dns_query_name, "www.example.com") == 0);
    flow_table_cleanup(&table);
}

static void test_flow_timeout_eviction_cleans_reassembly_state(void) {
    FlowTable table;
    PacketInfo first = make_tcp_packet(50000, 80);
    PacketInfo second = make_tcp_packet(50001, 80);
    FlowDirection direction;
    FlowInfo *flow;

    assert(flow_table_init(&table, 4, 64, 5));
    flow = flow_table_get_or_create(&table, &first, 10, &direction);
    assert(flow != NULL);
    assert(feed_segment(flow, direction, &first, 100, (const uint8_t *)"GET ", 4) ==
           APP_DECODE_NEED_MORE);
    assert(table.count == 1);
    assert(flow_table_get_or_create(&table, &second, 16, &direction) != NULL);
    assert(table.count == 1);
    flow_table_cleanup(&table);
}

static void test_max_flow_cap_evicts_oldest_flow(void) {
    FlowTable table;
    PacketInfo first = make_tcp_packet(50000, 80);
    PacketInfo second = make_tcp_packet(50001, 80);
    FlowDirection direction;

    assert(flow_table_init(&table, 1, 64, 60));
    assert(flow_table_get_or_create(&table, &first, 10, &direction) != NULL);
    assert(flow_table_get_or_create(&table, &second, 11, &direction) != NULL);
    assert(table.count == 1);
    assert(table.flows[0].key.a_port == 50001 || table.flows[0].key.b_port == 50001);
    flow_table_cleanup(&table);
}

static void test_max_stream_buffer_cap_prevents_classification(void) {
    FlowTable table;
    PacketInfo packet = make_tcp_packet(50000, 80);
    FlowDirection direction;
    FlowInfo *flow;
    const uint8_t payload[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    assert(flow_table_init(&table, 4, 8, 60));
    flow = flow_table_get_or_create(&table, &packet, 10, &direction);
    assert(flow != NULL);
    packet.tcp_sequence = 1;
    packet.payload = payload;
    packet.payload_decode_length = sizeof(payload) - 1;
    assert(tcp_reassembly_process_segment(&flow->directions[direction].tcp,
                                          packet.tcp_sequence,
                                          0,
                                          packet.payload,
                                          packet.payload_decode_length) ==
           TCP_REASSEMBLY_DROPPED);
    assert(!flow->app_classified);
    flow_table_cleanup(&table);
}

int main(void) {
    test_http_request_split_across_two_tcp_segments();
    test_http_headers_split_across_multiple_packets();
    test_tls_client_hello_split_across_two_segments();
    test_dns_over_tcp_split_across_two_segments();
    test_flow_timeout_eviction_cleans_reassembly_state();
    test_max_flow_cap_evicts_oldest_flow();
    test_max_stream_buffer_cap_prevents_classification();

    printf("All flow app decode tests passed.\n");

    return 0;
}
