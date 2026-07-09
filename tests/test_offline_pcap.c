#include <assert.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "capture.h"
#include "config.h"
#include "stats.h"

#define TEST_INPUT_PCAP "/tmp/minisniffer_offline_input.pcap"
#define TEST_OUTPUT_PCAP "/tmp/minisniffer_offline_output.pcap"

static size_t build_tcp_packet(unsigned char *packet, size_t packet_capacity, uint32_t sequence,
                               const uint8_t *payload, size_t payload_length) {
    const size_t ethernet_length = 14;
    const size_t ipv4_length = 20;
    const size_t tcp_length = 20;
    const size_t packet_length = ethernet_length + ipv4_length + tcp_length + payload_length;
    size_t ip = ethernet_length;
    size_t tcp = ethernet_length + ipv4_length;
    uint16_t total_length = (uint16_t)(ipv4_length + tcp_length + payload_length);

    assert(packet_length <= packet_capacity);
    memset(packet, 0, packet_length);

    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[ip] = 0x45;
    packet[ip + 2] = (uint8_t)(total_length >> 8);
    packet[ip + 3] = (uint8_t)total_length;
    packet[ip + 8] = 64;
    packet[ip + 9] = 6;
    packet[ip + 12] = 10;
    packet[ip + 15] = 1;
    packet[ip + 16] = 10;
    packet[ip + 19] = 2;

    packet[tcp] = 0xc3;
    packet[tcp + 1] = 0x50;
    packet[tcp + 3] = 80;
    packet[tcp + 4] = (uint8_t)(sequence >> 24);
    packet[tcp + 5] = (uint8_t)(sequence >> 16);
    packet[tcp + 6] = (uint8_t)(sequence >> 8);
    packet[tcp + 7] = (uint8_t)sequence;
    packet[tcp + 12] = 0x50;
    packet[tcp + 13] = 0x18;

    if (payload_length != 0) {
        memcpy(packet + ethernet_length + ipv4_length + tcp_length, payload, payload_length);
    }

    return packet_length;
}

static size_t build_udp_packet(unsigned char *packet, size_t packet_capacity,
                               const uint8_t *payload, size_t payload_length) {
    const size_t ethernet_length = 14;
    const size_t ipv4_length = 20;
    const size_t udp_length = 8;
    const size_t packet_length = ethernet_length + ipv4_length + udp_length + payload_length;
    size_t ip = ethernet_length;
    size_t udp = ethernet_length + ipv4_length;
    uint16_t total_length = (uint16_t)(ipv4_length + udp_length + payload_length);
    uint16_t udp_total_length = (uint16_t)(udp_length + payload_length);

    assert(packet_length <= packet_capacity);
    memset(packet, 0, packet_length);

    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[ip] = 0x45;
    packet[ip + 2] = (uint8_t)(total_length >> 8);
    packet[ip + 3] = (uint8_t)total_length;
    packet[ip + 8] = 64;
    packet[ip + 9] = 17;
    packet[ip + 12] = 10;
    packet[ip + 15] = 3;
    packet[ip + 16] = 10;
    packet[ip + 19] = 4;

    packet[udp] = 0x30;
    packet[udp + 1] = 0x39;
    packet[udp + 2] = 0x00;
    packet[udp + 3] = 0x35;
    packet[udp + 4] = (uint8_t)(udp_total_length >> 8);
    packet[udp + 5] = (uint8_t)udp_total_length;

    if (payload_length != 0) {
        memcpy(packet + ethernet_length + ipv4_length + udp_length, payload, payload_length);
    }

    return packet_length;
}

static void dump_packet(pcap_dumper_t *dumper, const unsigned char *packet, size_t packet_length,
                        long seconds) {
    struct pcap_pkthdr header;

    memset(&header, 0, sizeof(header));
    header.ts.tv_sec = seconds;
    header.ts.tv_usec = 123456;
    header.caplen = (bpf_u_int32)packet_length;
    header.len = (bpf_u_int32)packet_length;
    pcap_dump((u_char *)dumper, &header, packet);
}

static void write_fixture_pcap(const char *path) {
    static const uint8_t http_request[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    static const uint8_t udp_payload[] = "dns";
    unsigned char tcp_packet[256];
    unsigned char udp_packet[128];
    size_t tcp_length;
    size_t udp_length;
    pcap_t *dead;
    pcap_dumper_t *dumper;

    tcp_length = build_tcp_packet(tcp_packet, sizeof(tcp_packet), 100, http_request,
                                  sizeof(http_request) - 1);
    udp_length =
        build_udp_packet(udp_packet, sizeof(udp_packet), udp_payload, sizeof(udp_payload) - 1);

    unlink(path);
    dead = pcap_open_dead(DLT_EN10MB, 65535);
    assert(dead != NULL);
    dumper = pcap_dump_open(dead, path);
    assert(dumper != NULL);

    dump_packet(dumper, tcp_packet, tcp_length, 10);
    dump_packet(dumper, udp_packet, udp_length, 11);

    pcap_dump_close(dumper);
    pcap_close(dead);
}

static void test_offline_read_and_filtered_write(void) {
    AppConfig config;
    PacketStats stats;
    pcap_t *output;
    struct pcap_pkthdr *header = NULL;
    const unsigned char *packet = NULL;
    char error_buffer[PCAP_ERRBUF_SIZE];

    write_fixture_pcap(TEST_INPUT_PCAP);
    unlink(TEST_OUTPUT_PCAP);

    config_init_defaults(&config);
    config.read_path_enabled = true;
    snprintf(config.read_path, sizeof(config.read_path), "%s", TEST_INPUT_PCAP);
    config.write_path_enabled = true;
    snprintf(config.write_path, sizeof(config.write_path), "%s", TEST_OUTPUT_PCAP);
    config.filter_protocol_enabled = 1;
    config.filter_protocol = PROTO_TCP;
    config.quiet = true;

    stats_init(&stats);
    assert(capture_start(&config, &stats) == 0);
    assert(stats.total_packets == 1);
    assert(stats.tcp_packets == 1);
    assert(access(TEST_OUTPUT_PCAP, F_OK) == 0);

    output = pcap_open_offline(TEST_OUTPUT_PCAP, error_buffer);
    assert(output != NULL);
    assert(pcap_datalink(output) == DLT_EN10MB);
    assert(pcap_next_ex(output, &header, &packet) == 1);
    assert(header->ts.tv_sec == 10);
    assert(header->ts.tv_usec == 123456);
    assert(header->caplen > 0);
    assert(packet != NULL);
    assert(pcap_next_ex(output, &header, &packet) == -2);
    pcap_close(output);

    unlink(TEST_INPUT_PCAP);
    unlink(TEST_OUTPUT_PCAP);
}

int main(void) {
    test_offline_read_and_filtered_write();

    printf("All offline pcap tests passed.\n");
    return 0;
}
