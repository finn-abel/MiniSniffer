#include <string.h>

#include "bench_common.h"
#include "config.h"
#include "filters.h"

#define BENCH_ITERATIONS 500000

static PacketInfo make_packet(void) {
    static const unsigned char payload[] = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    PacketInfo packet;

    memset(&packet, 0, sizeof(packet));
    packet.protocol = PROTO_TCP;
    packet.has_ports = 1;
    packet.src_port = 51432;
    packet.dst_port = 443;
    snprintf(packet.src_ip, sizeof(packet.src_ip), "192.168.1.25");
    snprintf(packet.dst_ip, sizeof(packet.dst_ip), "93.184.216.34");
    packet.has_payload = 1;
    packet.payload = payload;
    packet.payload_capture_length = sizeof(payload) - 1;
    packet.payload_decode_length = sizeof(payload) - 1;
    return packet;
}

int main(void) {
    AppConfig config;
    PacketInfo packet = make_packet();
    FilterContext context;
    size_t i;
    double start;
    double elapsed;
    volatile int sink = 0;

    config_init_defaults(&config);
    config.filter_protocol_enabled = 1;
    config.filter_protocol = PROTO_TCP;
    config.filter_port_enabled = 1;
    config.filter_port = 443;
    config.filter_host_enabled = 1;
    snprintf(config.filter_host, sizeof(config.filter_host), "93.184.216.34");
    config.filter_payload_text_enabled = 1;
    memcpy(config.filter_payload_text, "Host:", 5);
    config.filter_payload_text_length = 5;

    context.packet = &packet;
    context.packet_app = NULL;
    context.flow_app = NULL;
    context.flow_is_classified = false;

    start = bench_now_seconds();
    for (i = 0; i < BENCH_ITERATIONS; i++) {
        sink += filters_match(&config, &context) ? 1 : 0;
    }
    elapsed = bench_now_seconds() - start;

    bench_report("filters_match(protocol+port+host+text)", BENCH_ITERATIONS, elapsed);
    (void)sink;
    return 0;
}
