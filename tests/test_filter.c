#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "filter.h"

static PacketInfo make_tcp_packet(void) {
    PacketInfo info;

    memset(&info, 0, sizeof(info));
    info.protocol = PROTO_TCP;
    info.src_port = 51432;
    info.dst_port = 443;
    info.has_ports = 1;
    snprintf(info.src_ip, sizeof(info.src_ip), "192.168.1.25");
    snprintf(info.dst_ip, sizeof(info.dst_ip), "142.250.190.14");

    return info;
}

static PacketInfo make_icmp_packet(void) {
    PacketInfo info;

    memset(&info, 0, sizeof(info));
    info.protocol = PROTO_ICMP;
    info.has_ports = 0;
    snprintf(info.src_ip, sizeof(info.src_ip), "192.168.1.25");
    snprintf(info.dst_ip, sizeof(info.dst_ip), "8.8.8.8");

    return info;
}

static void test_filter_packet_matches_when_filters_disabled(void) {
    AppConfig config;
    PacketInfo info = make_tcp_packet();

    config_init_defaults(&config);

    assert(filter_packet_matches(&config, &info) == 1);
}

static void test_filter_packet_matches_protocol(void) {
    AppConfig config;
    PacketInfo info = make_tcp_packet();

    config_init_defaults(&config);
    config.filter_protocol_enabled = 1;
    config.filter_protocol = PROTO_TCP;

    assert(filter_packet_matches(&config, &info) == 1);

    config.filter_protocol = PROTO_UDP;
    assert(filter_packet_matches(&config, &info) == 0);
}

static void test_filter_packet_matches_port(void) {
    AppConfig config;
    PacketInfo info = make_tcp_packet();

    config_init_defaults(&config);
    config.filter_port_enabled = 1;
    config.filter_port = 443;

    assert(filter_packet_matches(&config, &info) == 1);

    config.filter_port = 53;
    assert(filter_packet_matches(&config, &info) == 0);
}

static void test_filter_packet_rejects_port_filter_when_packet_has_no_ports(void) {
    AppConfig config;
    PacketInfo info = make_icmp_packet();

    config_init_defaults(&config);
    config.filter_port_enabled = 1;
    config.filter_port = 443;

    assert(filter_packet_matches(&config, &info) == 0);
}

static void test_filter_packet_matches_host(void) {
    AppConfig config;
    PacketInfo info = make_tcp_packet();

    config_init_defaults(&config);
    config.filter_host_enabled = 1;
    snprintf(config.filter_host, sizeof(config.filter_host), "142.250.190.14");

    assert(filter_packet_matches(&config, &info) == 1);

    snprintf(config.filter_host, sizeof(config.filter_host), "1.1.1.1");
    assert(filter_packet_matches(&config, &info) == 0);
}

static void test_filter_packet_requires_all_enabled_filters(void) {
    AppConfig config;
    PacketInfo info = make_tcp_packet();

    config_init_defaults(&config);
    config.filter_protocol_enabled = 1;
    config.filter_protocol = PROTO_TCP;
    config.filter_port_enabled = 1;
    config.filter_port = 443;
    config.filter_host_enabled = 1;
    snprintf(config.filter_host, sizeof(config.filter_host), "142.250.190.14");

    assert(filter_packet_matches(&config, &info) == 1);

    config.filter_port = 53;
    assert(filter_packet_matches(&config, &info) == 0);
}

static void test_filter_packet_rejects_null_inputs(void) {
    AppConfig config;
    PacketInfo info = make_tcp_packet();

    config_init_defaults(&config);

    assert(filter_packet_matches(NULL, &info) == 0);
    assert(filter_packet_matches(&config, NULL) == 0);
}

int main(void) {
    test_filter_packet_matches_when_filters_disabled();
    test_filter_packet_matches_protocol();
    test_filter_packet_matches_port();
    test_filter_packet_rejects_port_filter_when_packet_has_no_ports();
    test_filter_packet_matches_host();
    test_filter_packet_requires_all_enabled_filters();
    test_filter_packet_rejects_null_inputs();

    printf("All filter tests passed.\n");

    return 0;
}
