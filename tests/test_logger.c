#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "logger.h"

#define TEST_LOG_PATH "/tmp/minisniffer_test_logger.csv"

static PacketInfo make_tcp_packet(void) {
    PacketInfo info;

    memset(&info, 0, sizeof(info));
    info.packet_number = 1;
    info.protocol = PROTO_TCP;
    snprintf(info.src_ip, sizeof(info.src_ip), "192.168.1.25");
    snprintf(info.dst_ip, sizeof(info.dst_ip), "142.250.190.14");
    info.src_port = 51432;
    info.dst_port = 443;
    info.has_ports = 1;
    info.size = 1280;

    return info;
}

static PacketInfo make_icmp_packet(void) {
    PacketInfo info;

    memset(&info, 0, sizeof(info));
    info.packet_number = 3;
    info.protocol = PROTO_ICMP;
    snprintf(info.src_ip, sizeof(info.src_ip), "192.168.1.25");
    snprintf(info.dst_ip, sizeof(info.dst_ip), "8.8.8.8");
    info.size = 98;

    return info;
}

static PacketInfo make_payload_packet(void) {
    PacketInfo info = make_tcp_packet();

    info.payload = info.payload_preview;
    info.payload_capture_length = 5;
    info.payload_decode_length = 5;
    info.payload_preview_length = 5;
    info.has_payload = 1;
    memcpy(info.payload_preview, "GET /", 5);

    return info;
}

static void test_logger_open_rejects_invalid_path(void) {
    assert(logger_open(NULL) != 0);
    assert(logger_open("") != 0);
}

static void test_logger_writes_header_and_rows(void) {
    FILE *file;
    char line[256];
    PacketInfo tcp_info = make_tcp_packet();
    PacketInfo icmp_info = make_icmp_packet();

    remove(TEST_LOG_PATH);
    assert(logger_open(TEST_LOG_PATH) == 0);
    logger_write(&tcp_info);
    logger_write(&icmp_info);
    logger_close();

    file = fopen(TEST_LOG_PATH, "r");
    assert(file != NULL);

    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strcmp(line, "packet_number,protocol,src_ip,src_port,dst_ip,dst_port,size\n") == 0);

    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strcmp(line, "1,TCP,192.168.1.25,51432,142.250.190.14,443,1280\n") == 0);

    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strcmp(line, "3,ICMP,192.168.1.25,,8.8.8.8,,98\n") == 0);

    fclose(file);
    remove(TEST_LOG_PATH);
}

static void test_logger_writes_payload_columns_when_enabled(void) {
    FILE *file;
    char line[512];
    PacketInfo info = make_payload_packet();

    logger_set_payload_logging(1, 5);
    remove(TEST_LOG_PATH);
    assert(logger_open(TEST_LOG_PATH) == 0);
    logger_write(&info);
    logger_close();
    logger_set_payload_logging(0, 0);

    file = fopen(TEST_LOG_PATH, "r");
    assert(file != NULL);

    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strcmp(line,
                  "packet_number,protocol,src_ip,src_port,dst_ip,dst_port,size,payload_length,payload_hex,payload_ascii\n") == 0);

    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strcmp(line,
                  "1,TCP,192.168.1.25,51432,142.250.190.14,443,1280,5,\"47 45 54 20 2f\",\"GET /\"\n") == 0);

    fclose(file);
    remove(TEST_LOG_PATH);
}

static void test_logger_write_ignores_null_info(void) {
    remove(TEST_LOG_PATH);
    assert(logger_open(TEST_LOG_PATH) == 0);
    logger_write(NULL);
    logger_close();
    remove(TEST_LOG_PATH);
}

int main(void) {
    test_logger_open_rejects_invalid_path();
    test_logger_writes_header_and_rows();
    test_logger_writes_payload_columns_when_enabled();
    test_logger_write_ignores_null_info();

    printf("All logger tests passed.\n");

    return 0;
}
