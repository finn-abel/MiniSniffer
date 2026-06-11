#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_decoder.h"
#include "tcp_reassembly.h"

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

static void test_tcp_reassembly_drops_when_memory_cap_is_exceeded(void) {
    TcpReassemblyDirection state;

    assert(tcp_reassembly_direction_init(&state, 4));
    assert(tcp_reassembly_process_segment(&state, 100, 0, (const uint8_t *)"ABCDE", 5) ==
           TCP_REASSEMBLY_DROPPED);
    assert(stream_buffer_length(&state.stream) == 0);
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

int main(void) {
    test_tcp_reassembly_accepts_in_order_data();
    test_tcp_reassembly_ignores_exact_retransmission();
    test_tcp_reassembly_buffers_simple_out_of_order_data();
    test_tcp_reassembly_trims_overlap_predictably();
    test_tcp_reassembly_drops_when_memory_cap_is_exceeded();
    test_reassembled_http_feeds_existing_decoder();

    printf("All TCP reassembly tests passed.\n");

    return 0;
}
