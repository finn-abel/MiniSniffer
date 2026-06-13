#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "app_http.h"
#include "csv_logger.h"
#include "fixtures/app_fixtures.h"

#define TEST_CSV_LOG_PATH "/tmp/minisniffer_test_csv_logger.csv"
#define TEST_CSV_TARGET_PATH "/tmp/minisniffer_test_csv_target.txt"

static PacketInfo make_packet(void) {
    PacketInfo packet;

    memset(&packet, 0, sizeof(packet));
    snprintf(packet.timestamp, sizeof(packet.timestamp), "1710000000.123456");
    snprintf(packet.src_ip, sizeof(packet.src_ip), "192.168.1.25");
    snprintf(packet.dst_ip, sizeof(packet.dst_ip), "93.184.216.34");
    packet.protocol = PROTO_TCP;
    packet.has_ports = 1;
    packet.src_port = 51432;
    packet.dst_port = 80;
    packet.size = 512;

    return packet;
}

static AppInfo make_http_app(void) {
    AppInfo app;

    assert(app_http_decode(HTTP_GET_WITH_HOST,
                           sizeof(HTTP_GET_WITH_HOST) - 1,
                           &app) == APP_DECODE_OK);

    return app;
}

static void test_csv_logger_writes_app_schema(void) {
    FILE *file;
    char line[1024];
    PacketInfo packet = make_packet();
    AppInfo app = make_http_app();

    remove(TEST_CSV_LOG_PATH);
    assert(csv_logger_open(TEST_CSV_LOG_PATH, true, false, 0) == 0);
    assert(csv_logger_write_packet(&packet, &app, "packet") == 0);
    assert(csv_logger_close() == 0);

    file = fopen(TEST_CSV_LOG_PATH, "r");
    assert(file != NULL);

    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strcmp(line,
                  "timestamp,src_ip,src_port,dst_ip,dst_port,transport_protocol,packet_length,app_protocol,http_method,http_host,http_path,http_status,dns_query,dns_type,dns_class,dns_rcode,tls_sni,tls_alpn,tls_record_version,tls_client_version,app_source\n") == 0);

    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strcmp(line,
                  "\"1710000000.123456\",\"192.168.1.25\",51432,\"93.184.216.34\",80,TCP,512,http,\"GET\",\"example.com\",\"/index.html\",,\"\",,,0,\"\",\"\",,,\"packet\"\n") == 0);

    fclose(file);
    remove(TEST_CSV_LOG_PATH);
}

static void test_csv_logger_writes_none_app_source(void) {
    FILE *file;
    char line[1024];
    PacketInfo packet = make_packet();

    remove(TEST_CSV_LOG_PATH);
    assert(csv_logger_open(TEST_CSV_LOG_PATH, true, false, 0) == 0);
    assert(csv_logger_write_packet(&packet, NULL, "none") == 0);
    assert(csv_logger_close() == 0);

    file = fopen(TEST_CSV_LOG_PATH, "r");
    assert(file != NULL);
    assert(fgets(line, sizeof(line), file) != NULL);
    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strstr(line, ",none,") == NULL);
    assert(strstr(line, "\"none\"") != NULL);

    fclose(file);
    remove(TEST_CSV_LOG_PATH);
}

static void test_csv_logger_escapes_quotes_and_commas(void) {
    FILE *file;
    char line[1024];
    PacketInfo packet = make_packet();
    AppInfo app;

    memset(&app, 0, sizeof(app));
    app.protocol = APP_PROTO_HTTP;
    snprintf(app.http_method, sizeof(app.http_method), "GE\"T");
    snprintf(app.http_host, sizeof(app.http_host), "exa\"mple,com");
    snprintf(app.http_path, sizeof(app.http_path), "/a,\"b\"");
    snprintf(app.tls_alpn, sizeof(app.tls_alpn), "h2,\"http/1.1\"");

    remove(TEST_CSV_LOG_PATH);
    assert(csv_logger_open(TEST_CSV_LOG_PATH, true, false, 0) == 0);
    assert(csv_logger_write_packet(&packet, &app, "packet") == 0);
    assert(csv_logger_close() == 0);

    file = fopen(TEST_CSV_LOG_PATH, "r");
    assert(file != NULL);
    assert(fgets(line, sizeof(line), file) != NULL);
    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strcmp(line,
                  "\"1710000000.123456\",\"192.168.1.25\",51432,\"93.184.216.34\",80,TCP,512,http,\"GE\"\"T\",\"exa\"\"mple,com\",\"/a,\"\"b\"\"\",,\"\",,,0,\"\",\"h2,\"\"http/1.1\"\"\",,,\"packet\"\n") == 0);

    fclose(file);
    remove(TEST_CSV_LOG_PATH);
}

static void test_csv_logger_refuses_existing_files_and_uses_private_permissions(void) {
    FILE *file;
    struct stat status;

    remove(TEST_CSV_LOG_PATH);
    assert(csv_logger_open(TEST_CSV_LOG_PATH, false, false, 0) == 0);
    assert(stat(TEST_CSV_LOG_PATH, &status) == 0);
    assert((status.st_mode & 0777) == 0600);
    assert(csv_logger_close() == 0);

    file = fopen(TEST_CSV_LOG_PATH, "r");
    assert(file != NULL);
    fclose(file);
    assert(csv_logger_open(TEST_CSV_LOG_PATH, false, false, 0) != 0);
    remove(TEST_CSV_LOG_PATH);
}

static void test_csv_logger_neutralizes_formulas_and_control_bytes(void) {
    FILE *file;
    char line[1024];
    PacketInfo packet = make_packet();
    AppInfo app;

    memset(&app, 0, sizeof(app));
    app.protocol = APP_PROTO_HTTP;
    snprintf(app.http_host, sizeof(app.http_host), "=CMD\nnext");

    remove(TEST_CSV_LOG_PATH);
    assert(csv_logger_open(TEST_CSV_LOG_PATH, true, false, 0) == 0);
    assert(csv_logger_write_packet(&packet, &app, "packet") == 0);
    assert(csv_logger_close() == 0);

    file = fopen(TEST_CSV_LOG_PATH, "r");
    assert(file != NULL);
    assert(fgets(line, sizeof(line), file) != NULL);
    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strstr(line, "\"'=CMD\\x0anext\"") != NULL);
    assert(strchr(line, '\n') == line + strlen(line) - 1);
    fclose(file);
    remove(TEST_CSV_LOG_PATH);
}

static void test_csv_logger_refuses_symlink_paths(void) {
    FILE *file;
    char content[16];

    remove(TEST_CSV_LOG_PATH);
    remove(TEST_CSV_TARGET_PATH);
    file = fopen(TEST_CSV_TARGET_PATH, "w");
    assert(file != NULL);
    assert(fputs("keep", file) >= 0);
    fclose(file);
    assert(symlink(TEST_CSV_TARGET_PATH, TEST_CSV_LOG_PATH) == 0);

    assert(csv_logger_open(TEST_CSV_LOG_PATH, false, false, 0) != 0);
    file = fopen(TEST_CSV_TARGET_PATH, "r");
    assert(file != NULL);
    assert(fgets(content, sizeof(content), file) != NULL);
    assert(strcmp(content, "keep") == 0);
    fclose(file);

    remove(TEST_CSV_LOG_PATH);
    remove(TEST_CSV_TARGET_PATH);
}

static void test_csv_logger_writes_payload_schema_variants(void) {
    FILE *file;
    char line[1024];
    PacketInfo packet = make_packet();

    packet.has_ports = 0;
    packet.has_payload = 1;
    packet.payload_capture_length = 4;
    packet.payload_preview_length = 4;
    packet.payload_preview[0] = ' ';
    packet.payload_preview[1] = '+';
    packet.payload_preview[2] = '"';
    packet.payload_preview[3] = 0x01;

    remove(TEST_CSV_LOG_PATH);
    assert(csv_logger_open(TEST_CSV_LOG_PATH, false, true, 4) == 0);
    assert(csv_logger_write_packet(&packet, NULL, NULL) == 0);
    packet.has_payload = 0;
    assert(csv_logger_write_packet(&packet, NULL, NULL) == 0);
    assert(csv_logger_close() == 0);

    file = fopen(TEST_CSV_LOG_PATH, "r");
    assert(file != NULL);
    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strstr(line, "payload_hex") != NULL);
    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strstr(line, "20 2b 22 01") != NULL);
    assert(strstr(line, "' +\"\".") != NULL);
    assert(fgets(line, sizeof(line), file) != NULL);
    fclose(file);
    remove(TEST_CSV_LOG_PATH);
}

static void test_csv_logger_caps_payload_preview_limit(void) {
    FILE *file;
    char line[1024];
    PacketInfo packet = make_packet();

    packet.has_payload = 1;
    packet.payload_capture_length = 4;
    packet.payload_preview_length = 4;
    memcpy(packet.payload_preview, "ABCD", 4);

    remove(TEST_CSV_LOG_PATH);
    assert(csv_logger_open(TEST_CSV_LOG_PATH,
                           false,
                           true,
                           MINISNIFFER_MAX_PAYLOAD_PREVIEW_BYTES + 1) == 0);
    assert(csv_logger_close() == 0);
    remove(TEST_CSV_LOG_PATH);

    assert(csv_logger_open(TEST_CSV_LOG_PATH, false, true, 2) == 0);
    assert(csv_logger_write_packet(&packet, NULL, NULL) == 0);
    assert(csv_logger_close() == 0);
    file = fopen(TEST_CSV_LOG_PATH, "r");
    assert(file != NULL);
    assert(fgets(line, sizeof(line), file) != NULL);
    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strstr(line, "41 42") != NULL);
    assert(strstr(line, "41 42 43") == NULL);
    fclose(file);
    remove(TEST_CSV_LOG_PATH);
}

static void test_csv_logger_writes_dns_tls_and_optional_fields(void) {
    FILE *file;
    char line[1024];
    PacketInfo packet = make_packet();
    AppInfo app;

    memset(&app, 0, sizeof(app));
    app.protocol = APP_PROTO_DNS;
    app.http_status_code = 201;
    snprintf(app.dns_query_name, sizeof(app.dns_query_name), "example.com");
    app.dns_query_type = 28;
    app.dns_query_class = 1;
    app.dns_rcode = 3;
    app.tls_record_version = 0x0303;
    app.tls_client_version = 0x0304;
    snprintf(app.tls_sni, sizeof(app.tls_sni), "  +formula");
    snprintf(app.tls_alpn, sizeof(app.tls_alpn), "-danger");
    packet.has_ports = 0;

    remove(TEST_CSV_LOG_PATH);
    assert(csv_logger_open(TEST_CSV_LOG_PATH, true, false, 0) == 0);
    assert(csv_logger_write_packet(&packet, &app, "invalid") == 0);
    app.protocol = APP_PROTO_TLS;
    snprintf(app.tls_sni, sizeof(app.tls_sni), "@command");
    assert(csv_logger_write_packet(&packet, &app, "flow") == 0);
    assert(csv_logger_close() == 0);

    file = fopen(TEST_CSV_LOG_PATH, "r");
    assert(file != NULL);
    assert(fgets(line, sizeof(line), file) != NULL);
    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strstr(line, ",dns,") != NULL);
    assert(strstr(line, ",201,") != NULL);
    assert(strstr(line, ",28,1,3,") != NULL);
    assert(strstr(line, "0x0303,0x0304") != NULL);
    assert(strstr(line, "\"none\"") != NULL);
    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strstr(line, ",tls,") != NULL);
    assert(strstr(line, "\"'@command\"") != NULL);
    assert(strstr(line, "\"flow\"") != NULL);
    fclose(file);
    remove(TEST_CSV_LOG_PATH);
}

static void test_csv_logger_public_guards(void) {
    PacketInfo packet = make_packet();

    assert(csv_logger_open(NULL, false, false, 0) != 0);
    assert(csv_logger_open("", false, false, 0) != 0);
    assert(csv_logger_write_packet(&packet, NULL, NULL) == 0);
    assert(csv_logger_write_packet(NULL, NULL, NULL) == 0);
    assert(csv_logger_close() == 0);
}

int main(void) {
    test_csv_logger_writes_app_schema();
    test_csv_logger_writes_none_app_source();
    test_csv_logger_escapes_quotes_and_commas();
    test_csv_logger_refuses_existing_files_and_uses_private_permissions();
    test_csv_logger_neutralizes_formulas_and_control_bytes();
    test_csv_logger_refuses_symlink_paths();
    test_csv_logger_writes_payload_schema_variants();
    test_csv_logger_caps_payload_preview_limit();
    test_csv_logger_writes_dns_tls_and_optional_fields();
    test_csv_logger_public_guards();

    printf("All CSV logger tests passed.\n");

    return 0;
}
