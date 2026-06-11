#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "app_http.h"
#include "csv_logger.h"
#include "fixtures/app_fixtures.h"

#define TEST_CSV_LOG_PATH "/tmp/minisniffer_test_csv_logger.csv"

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

    assert(csv_logger_open(TEST_CSV_LOG_PATH, true, false, 0) == 0);
    csv_logger_write_packet(&packet, &app, "packet");
    csv_logger_close();

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

    assert(csv_logger_open(TEST_CSV_LOG_PATH, true, false, 0) == 0);
    csv_logger_write_packet(&packet, NULL, "none");
    csv_logger_close();

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

    assert(csv_logger_open(TEST_CSV_LOG_PATH, true, false, 0) == 0);
    csv_logger_write_packet(&packet, &app, "packet");
    csv_logger_close();

    file = fopen(TEST_CSV_LOG_PATH, "r");
    assert(file != NULL);
    assert(fgets(line, sizeof(line), file) != NULL);
    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strcmp(line,
                  "\"1710000000.123456\",\"192.168.1.25\",51432,\"93.184.216.34\",80,TCP,512,http,\"GE\"\"T\",\"exa\"\"mple,com\",\"/a,\"\"b\"\"\",,\"\",,,0,\"\",\"h2,\"\"http/1.1\"\"\",,,\"packet\"\n") == 0);

    fclose(file);
    remove(TEST_CSV_LOG_PATH);
}

int main(void) {
    test_csv_logger_writes_app_schema();
    test_csv_logger_writes_none_app_source();
    test_csv_logger_escapes_quotes_and_commas();

    printf("All CSV logger tests passed.\n");

    return 0;
}
