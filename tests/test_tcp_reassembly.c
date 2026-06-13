#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_decoder.h"
#include "tcp_reassembly.h"

#define tcp_reassembly_direction_cleanup tcp_reassembly_direction_cleanup_white_box
#define tcp_reassembly_direction_init tcp_reassembly_direction_init_white_box
#define tcp_reassembly_process_segment tcp_reassembly_process_segment_white_box
#include "../src/tcp_reassembly.c"
#undef tcp_reassembly_direction_cleanup
#undef tcp_reassembly_direction_init
#undef tcp_reassembly_process_segment

static void test_tcp_reassembly_accepts_in_order_data(void) {
    TcpReassemblyDirection state;

    assert(tcp_reassembly_direction_init(&state, 64));
    assert(tcp_reassembly_process_segment(&state,
                                          100,
                                          0,
                                          (const uint8_t *)"GET ",
                                          4) == TCP_REASSEMBLY_ACCEPTED);
    assert(state.initial_sequence_known);
    assert(state.next_sequence == 104);
    assert(stream_buffer_length(&state.stream) == 4);
    assert(memcmp(stream_buffer_data(&state.stream), "GET ", 4) == 0);
    tcp_reassembly_direction_cleanup(&state);
}

static void test_tcp_reassembly_ignores_exact_retransmission(void) {
    TcpReassemblyDirection state;

    assert(tcp_reassembly_direction_init(&state, 64));
    assert(tcp_reassembly_process_segment(&state, 100, 0, (const uint8_t *)"ABC", 3) ==
           TCP_REASSEMBLY_ACCEPTED);
    assert(tcp_reassembly_process_segment(&state, 100, 0, (const uint8_t *)"ABC", 3) ==
           TCP_REASSEMBLY_IGNORED);
    assert(state.retransmissions == 1);
    assert(stream_buffer_length(&state.stream) == 3);
    tcp_reassembly_direction_cleanup(&state);
}

static void test_tcp_reassembly_buffers_simple_out_of_order_data(void) {
    TcpReassemblyDirection state;

    assert(tcp_reassembly_direction_init(&state, 64));
    assert(tcp_reassembly_process_segment(&state, 100, 0, (const uint8_t *)"GET ", 4) ==
           TCP_REASSEMBLY_ACCEPTED);
    assert(tcp_reassembly_process_segment(&state, 110, 0, (const uint8_t *)"\r\n\r\n", 4) ==
           TCP_REASSEMBLY_BUFFERED);
    assert(tcp_reassembly_process_segment(&state, 104, 0, (const uint8_t *)"/ HTTP", 6) ==
           TCP_REASSEMBLY_ACCEPTED);
    assert(state.out_of_order_segments == 1);
    assert(state.gaps == 1);
    assert(stream_buffer_length(&state.stream) == 14);
    assert(memcmp(stream_buffer_data(&state.stream), "GET / HTTP\r\n\r\n", 14) == 0);
    tcp_reassembly_direction_cleanup(&state);
}

static void test_tcp_reassembly_records_gap_without_advancing_stream(void) {
    TcpReassemblyDirection state;

    assert(tcp_reassembly_direction_init(&state, 64));
    assert(tcp_reassembly_process_segment(&state, 100, 0, (const uint8_t *)"ABC", 3) ==
           TCP_REASSEMBLY_ACCEPTED);
    assert(tcp_reassembly_process_segment(&state, 108, 0, (const uint8_t *)"XYZ", 3) ==
           TCP_REASSEMBLY_BUFFERED);
    assert(state.gaps == 1);
    assert(state.out_of_order_segments == 1);
    assert(state.next_sequence == 103);
    assert(stream_buffer_length(&state.stream) == 3);
    assert(memcmp(stream_buffer_data(&state.stream), "ABC", 3) == 0);
    tcp_reassembly_direction_cleanup(&state);
}

static void test_tcp_reassembly_trims_overlap_predictably(void) {
    TcpReassemblyDirection state;

    assert(tcp_reassembly_direction_init(&state, 64));
    assert(tcp_reassembly_process_segment(&state, 100, 0, (const uint8_t *)"ABCDE", 5) ==
           TCP_REASSEMBLY_ACCEPTED);
    assert(tcp_reassembly_process_segment(&state, 103, 0, (const uint8_t *)"DEFG", 4) ==
           TCP_REASSEMBLY_ACCEPTED);
    assert(state.overlapping_segments == 1);
    assert(stream_buffer_length(&state.stream) == 7);
    assert(memcmp(stream_buffer_data(&state.stream), "ABCDEFG", 7) == 0);
    tcp_reassembly_direction_cleanup(&state);
}

static void test_tcp_reassembly_tracks_fin_and_rst(void) {
    TcpReassemblyDirection fin_state;
    TcpReassemblyDirection rst_state;

    assert(tcp_reassembly_direction_init(&fin_state, 64));
    assert(tcp_reassembly_process_segment(&fin_state,
                                          100,
                                          TCP_FLAG_FIN,
                                          NULL,
                                          0) == TCP_REASSEMBLY_ACCEPTED);
    assert(fin_state.fin_seen);
    assert(fin_state.next_sequence == 101);
    tcp_reassembly_direction_cleanup(&fin_state);

    assert(tcp_reassembly_direction_init(&rst_state, 64));
    assert(tcp_reassembly_process_segment(&rst_state,
                                          200,
                                          TCP_FLAG_RST,
                                          NULL,
                                          0) == TCP_REASSEMBLY_ACCEPTED);
    assert(rst_state.rst_seen);
    tcp_reassembly_direction_cleanup(&rst_state);
}

static void test_tcp_reassembly_drops_when_memory_cap_is_exceeded(void) {
    TcpReassemblyDirection state;

    assert(tcp_reassembly_direction_init(&state, 4));
    assert(tcp_reassembly_process_segment(&state, 100, 0, (const uint8_t *)"ABCDE", 5) ==
           TCP_REASSEMBLY_DROPPED);
    assert(stream_buffer_length(&state.stream) == 0);
    assert(state.unusable);
    assert(tcp_reassembly_process_segment(&state, 105, 0, (const uint8_t *)"F", 1) ==
           TCP_REASSEMBLY_DROPPED);
    tcp_reassembly_direction_cleanup(&state);
}

static void test_tcp_reassembly_handles_sequence_wraparound(void) {
    TcpReassemblyDirection state;

    assert(tcp_reassembly_direction_init(&state, 64));
    assert(tcp_reassembly_process_segment(&state,
                                          UINT32_MAX - 1,
                                          0,
                                          (const uint8_t *)"ABC",
                                          3) == TCP_REASSEMBLY_ACCEPTED);
    assert(state.next_sequence == 1);
    assert(tcp_reassembly_process_segment(&state, 1, 0, (const uint8_t *)"D", 1) ==
           TCP_REASSEMBLY_ACCEPTED);
    assert(state.next_sequence == 2);
    assert(memcmp(stream_buffer_data(&state.stream), "ABCD", 4) == 0);
    tcp_reassembly_direction_cleanup(&state);
}

static void test_reassembled_http_feeds_existing_decoder(void) {
    TcpReassemblyDirection state;
    AppInfo app;
    const uint8_t tail[] = " HTTP/1.1\r\nHost: example.com\r\n\r\n";

    assert(tcp_reassembly_direction_init(&state, 128));
    assert(tcp_reassembly_process_segment(&state,
                                          1,
                                          0,
                                          (const uint8_t *)"GET /",
                                          5) == TCP_REASSEMBLY_ACCEPTED);
    assert(app_decode_buffer(APP_PROTO_HTTP,
                             stream_buffer_data(&state.stream),
                             stream_buffer_length(&state.stream),
                             &app) == APP_DECODE_NEED_MORE);
    assert(tcp_reassembly_process_segment(&state, 6, 0, tail, sizeof(tail) - 1) ==
           TCP_REASSEMBLY_ACCEPTED);
    assert(app_decode_buffer(APP_PROTO_HTTP,
                             stream_buffer_data(&state.stream),
                             stream_buffer_length(&state.stream),
                             &app) == APP_DECODE_OK);
    assert(strcmp(app.http_method, "GET") == 0);
    assert(strcmp(app.http_host, "example.com") == 0);
    tcp_reassembly_direction_cleanup(&state);
}

static void test_tcp_reassembly_rejects_invalid_inputs(void) {
    TcpReassemblyDirection state;
    uint8_t value = 1;

    assert(!tcp_reassembly_direction_init(NULL, 4));
    assert(!tcp_reassembly_direction_init(&state, 0));
    tcp_reassembly_direction_cleanup(NULL);
    clear_pending_segment(NULL);
    remove_pending_at(NULL, 0);

    memset(&state, 0, sizeof(state));
    remove_pending_at(&state, 0);
    assert(tcp_reassembly_process_segment(NULL, 1, 0, &value, 1) ==
           TCP_REASSEMBLY_DROPPED);
    state.unusable = true;
    assert(tcp_reassembly_process_segment(&state, 1, 0, &value, 1) ==
           TCP_REASSEMBLY_DROPPED);
}

static void test_tcp_reassembly_pending_removal_compacts_entries(void) {
    TcpReassemblyDirection state;

    memset(&state, 0, sizeof(state));
    state.pending_count = 2;
    state.pending_bytes = 1;
    state.pending[0].data = malloc(2);
    state.pending[0].length = 2;
    state.pending[1].data = malloc(1);
    state.pending[1].length = 1;
    state.pending[1].sequence = 10;
    assert(state.pending[0].data != NULL);
    assert(state.pending[1].data != NULL);

    remove_pending_at(&state, 0);
    assert(state.pending_count == 1);
    assert(state.pending_bytes == 0);
    assert(state.pending[0].sequence == 10);
    clear_pending_segment(&state.pending[0]);
}

static void test_tcp_reassembly_flushes_retransmitted_pending_segment(void) {
    TcpReassemblyDirection state;

    assert(tcp_reassembly_direction_init_white_box(&state, 16));
    state.initial_sequence_known = true;
    state.next_sequence = 105;
    assert(store_out_of_order_segment(&state, 100, (const uint8_t *)"ABC", 3));
    assert(flush_pending_segments(&state));
    assert(state.pending_count == 0);
    assert(state.retransmissions == 1);
    tcp_reassembly_direction_cleanup_white_box(&state);
}

static void test_tcp_reassembly_flushes_overlapping_pending_tail(void) {
    TcpReassemblyDirection state;

    assert(tcp_reassembly_direction_init_white_box(&state, 16));
    state.initial_sequence_known = true;
    state.next_sequence = 102;
    assert(store_out_of_order_segment(&state, 100, (const uint8_t *)"ABCD", 4));
    assert(flush_pending_segments(&state));
    assert(state.pending_count == 0);
    assert(state.overlapping_segments == 1);
    assert(state.next_sequence == 104);
    assert(memcmp(stream_buffer_data(&state.stream), "CD", 2) == 0);
    tcp_reassembly_direction_cleanup_white_box(&state);
}

static void test_tcp_reassembly_marks_unusable_on_append_failures(void) {
    TcpReassemblyDirection state;

    assert(tcp_reassembly_direction_init(&state, 4));
    assert(tcp_reassembly_process_segment(&state, 100, 0, (const uint8_t *)"ABCD", 4) ==
           TCP_REASSEMBLY_ACCEPTED);
    assert(tcp_reassembly_process_segment(&state, 104, 0, (const uint8_t *)"E", 1) ==
           TCP_REASSEMBLY_DROPPED);
    assert(state.unusable);
    tcp_reassembly_direction_cleanup(&state);

    assert(tcp_reassembly_direction_init_white_box(&state, 4));
    assert(stream_buffer_append(&state.stream, (const uint8_t *)"ABCD", 4));
    state.initial_sequence_known = true;
    state.next_sequence = 102;
    assert(store_out_of_order_segment(&state, 100, (const uint8_t *)"ABCDE", 5) == false);
    state.pending_byte_cap = 8;
    assert(store_out_of_order_segment(&state, 100, (const uint8_t *)"ABCDE", 5));
    assert(!flush_pending_segments(&state));
    assert(state.unusable);
    tcp_reassembly_direction_cleanup_white_box(&state);
}

static void test_tcp_reassembly_pending_store_limits(void) {
    TcpReassemblyDirection state;
    uint8_t value = 1;

    memset(&state, 0, sizeof(state));
    state.pending_byte_cap = 4;
    assert(!store_out_of_order_segment(&state, 1, NULL, 1));
    assert(!store_out_of_order_segment(&state, 1, &value, 0));
    assert(!store_out_of_order_segment(&state, 1, &value, 5));
    state.pending_bytes = 4;
    assert(!store_out_of_order_segment(&state, 1, &value, 1));
    state.pending_count = TCP_REASSEMBLY_MAX_PENDING_SEGMENTS;
    assert(!store_out_of_order_segment(&state, 1, &value, 1));
}

static void test_tcp_reassembly_handles_syn_fin_and_pending_limit(void) {
    TcpReassemblyDirection state;

    assert(payload_sequence(10, TCP_FLAG_SYN) == 11);
    assert(tcp_reassembly_direction_init(&state, 8));
    assert(tcp_reassembly_process_segment(&state,
                                          100,
                                          TCP_FLAG_SYN | TCP_FLAG_FIN,
                                          (const uint8_t *)"A",
                                          1) == TCP_REASSEMBLY_ACCEPTED);
    assert(state.next_sequence == 103);
    tcp_reassembly_direction_cleanup(&state);

    assert(tcp_reassembly_direction_init(&state, 8));
    assert(tcp_reassembly_process_segment(&state, 100, 0, (const uint8_t *)"A", 1) ==
           TCP_REASSEMBLY_ACCEPTED);
    state.pending_count = TCP_REASSEMBLY_MAX_PENDING_SEGMENTS;
    assert(tcp_reassembly_process_segment(&state, 110, 0, (const uint8_t *)"B", 1) ==
           TCP_REASSEMBLY_DROPPED);
    state.pending_count = 0;
    tcp_reassembly_direction_cleanup(&state);
}

static void test_tcp_reassembly_rejects_null_and_huge_payloads(void) {
    TcpReassemblyDirection state;
    uint8_t value = 1;

    assert(tcp_reassembly_direction_init(&state, 8));
    assert(tcp_reassembly_process_segment(&state, 1, 0, NULL, 1) ==
           TCP_REASSEMBLY_DROPPED);
    tcp_reassembly_direction_cleanup(&state);

    memset(&state, 0, sizeof(state));
    state.stream.capacity = SIZE_MAX;
    assert(tcp_reassembly_process_segment(&state,
                                          1,
                                          0,
                                          &value,
                                          (size_t)UINT32_MAX + 1) == TCP_REASSEMBLY_DROPPED);
}

int main(void) {
    test_tcp_reassembly_accepts_in_order_data();
    test_tcp_reassembly_ignores_exact_retransmission();
    test_tcp_reassembly_buffers_simple_out_of_order_data();
    test_tcp_reassembly_records_gap_without_advancing_stream();
    test_tcp_reassembly_trims_overlap_predictably();
    test_tcp_reassembly_tracks_fin_and_rst();
    test_tcp_reassembly_drops_when_memory_cap_is_exceeded();
    test_tcp_reassembly_handles_sequence_wraparound();
    test_reassembled_http_feeds_existing_decoder();
    test_tcp_reassembly_rejects_invalid_inputs();
    test_tcp_reassembly_pending_removal_compacts_entries();
    test_tcp_reassembly_flushes_retransmitted_pending_segment();
    test_tcp_reassembly_flushes_overlapping_pending_tail();
    test_tcp_reassembly_marks_unusable_on_append_failures();
    test_tcp_reassembly_pending_store_limits();
    test_tcp_reassembly_handles_syn_fin_and_pending_limit();
    test_tcp_reassembly_rejects_null_and_huge_payloads();

    printf("All TCP reassembly tests passed.\n");

    return 0;
}
