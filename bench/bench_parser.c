#include <string.h>

#include "bench_common.h"
#include "parser.h"

#define BENCH_ITERATIONS 500000

/*
 * A synthetic Ethernet + IPv4 + TCP packet carrying a small HTTP-shaped
 * payload, close to a typical short request MiniSniffer would parse in a
 * live capture.
 */
static size_t build_tcp_packet(unsigned char *packet, size_t capacity) {
    static const unsigned char payload[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const size_t ethernet_length = 14;
    const size_t ipv4_length = 20;
    const size_t tcp_length = 20;
    const size_t payload_length = sizeof(payload) - 1;
    const size_t total_length = ethernet_length + ipv4_length + tcp_length + payload_length;
    size_t ip = ethernet_length;
    size_t tcp = ethernet_length + ipv4_length;
    uint16_t ip_total_length = (uint16_t)(ipv4_length + tcp_length + payload_length);

    if (capacity < total_length) {
        return 0;
    }
    memset(packet, 0, total_length);

    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[ip] = 0x45;
    packet[ip + 2] = (unsigned char)(ip_total_length >> 8);
    packet[ip + 3] = (unsigned char)ip_total_length;
    packet[ip + 8] = 64;
    packet[ip + 9] = 6;
    packet[ip + 12] = 10;
    packet[ip + 15] = 1;
    packet[ip + 16] = 10;
    packet[ip + 19] = 2;

    packet[tcp] = 0xc3;
    packet[tcp + 1] = 0x50;
    packet[tcp + 3] = 80;
    packet[tcp + 12] = 0x50;
    packet[tcp + 13] = 0x18;

    memcpy(packet + ethernet_length + ipv4_length + tcp_length, payload, payload_length);
    return total_length;
}

int main(void) {
    unsigned char packet[128];
    size_t packet_length = build_tcp_packet(packet, sizeof(packet));
    PacketInfo info;
    size_t i;
    double start;
    double elapsed;
    volatile int sink = 0;

    start = bench_now_seconds();
    for (i = 0; i < BENCH_ITERATIONS; i++) {
        sink += parser_parse_packet(packet, packet_length, &info);
    }
    elapsed = bench_now_seconds() - start;

    bench_report("parser_parse_packet", BENCH_ITERATIONS, elapsed);
    (void)sink;
    return 0;
}
