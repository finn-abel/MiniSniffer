#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "output.h"

static void test_output_print_packet_app_accepts_protocols(void) {
    AppInfo app;

    memset(&app, 0, sizeof(app));
    app.protocol = APP_PROTO_HTTP;
    snprintf(app.http_method, sizeof(app.http_method), "GET");
    snprintf(app.http_host, sizeof(app.http_host), "example.com");
    snprintf(app.http_path, sizeof(app.http_path), "/");
    output_print_packet_app(&app);

    memset(&app, 0, sizeof(app));
    app.protocol = APP_PROTO_DNS;
    snprintf(app.dns_query_name, sizeof(app.dns_query_name), "example.com");
    app.dns_query_type = 1;
    output_print_packet_app(&app);

    memset(&app, 0, sizeof(app));
    app.protocol = APP_PROTO_TLS;
    snprintf(app.tls_sni, sizeof(app.tls_sni), "example.com");
    snprintf(app.tls_alpn, sizeof(app.tls_alpn), "h2,http/1.1");
    output_print_packet_app(&app);
}

static void test_output_print_flow_app_event_accepts_flow(void) {
    FlowInfo flow;

    memset(&flow, 0, sizeof(flow));
    flow.key.a_ip.ipv4 = 0xc0a80119;
    flow.key.a_port = 51432;
    flow.key.b_ip.ipv4 = 0x5db8d822;
    flow.key.b_port = 443;
    flow.key.transport_protocol = 6;
    flow.app.protocol = APP_PROTO_TLS;
    snprintf(flow.app.tls_sni, sizeof(flow.app.tls_sni), "example.com");
    snprintf(flow.app.tls_alpn, sizeof(flow.app.tls_alpn), "h2");

    output_print_flow_app_event(&flow);
}

static void test_output_escapes_terminal_control_bytes(void) {
    AppInfo app;
    FILE *capture;
    int saved_stdout;
    char output[512];
    size_t length;

    memset(&app, 0, sizeof(app));
    app.protocol = APP_PROTO_HTTP;
    snprintf(app.http_host, sizeof(app.http_host), "evil%c]0;owned%c", 0x1b, 0x07);

    capture = tmpfile();
    assert(capture != NULL);
    saved_stdout = dup(STDOUT_FILENO);
    assert(saved_stdout >= 0);
    assert(fflush(stdout) == 0);
    assert(dup2(fileno(capture), STDOUT_FILENO) >= 0);

    output_print_packet_app(&app);
    assert(fflush(stdout) == 0);
    assert(dup2(saved_stdout, STDOUT_FILENO) >= 0);
    close(saved_stdout);

    rewind(capture);
    length = fread(output, 1, sizeof(output) - 1, capture);
    output[length] = '\0';
    fclose(capture);

    assert(strchr(output, 0x1b) == NULL);
    assert(strstr(output, "evil\\x1b]0;owned\\x07") != NULL);
}

static void test_output_print_packet_app_handles_optional_fields(void) {
    AppInfo app;
    uint16_t dns_types[] = {0, 2, 5, 28, 255};
    size_t i;

    output_print_packet_app(NULL);
    memset(&app, 0, sizeof(app));
    output_print_packet_app(&app);

    app.protocol = APP_PROTO_HTTP;
    app.http_status_code = 204;
    snprintf(app.http_host, sizeof(app.http_host), "example.com\\path");
    output_print_packet_app(&app);

    for (i = 0; i < sizeof(dns_types) / sizeof(dns_types[0]); i++) {
        memset(&app, 0, sizeof(app));
        app.protocol = APP_PROTO_DNS;
        app.dns_query_type = dns_types[i];
        output_print_packet_app(&app);
    }
}

static void test_output_print_flow_app_event_handles_all_protocols(void) {
    FlowInfo flow;

    output_print_flow_app_event(NULL);
    memset(&flow, 0, sizeof(flow));
    output_print_flow_app_event(&flow);

    flow.key.a_ip.ipv4 = 0x0a000001;
    flow.key.a_port = 1234;
    flow.key.b_ip.ipv4 = 0x0a000002;
    flow.key.b_port = 80;
    flow.key.transport_protocol = 17;
    flow.app.protocol = APP_PROTO_HTTP;
    flow.app.http_status_code = 201;
    snprintf(flow.app.http_method, sizeof(flow.app.http_method), "POST");
    output_print_flow_app_event(&flow);

    memset(&flow.app, 0, sizeof(flow.app));
    flow.key.transport_protocol = 99;
    flow.app.protocol = APP_PROTO_DNS;
    flow.app.dns_query_type = 28;
    snprintf(flow.app.dns_query_name, sizeof(flow.app.dns_query_name), "example.com");
    output_print_flow_app_event(&flow);

    memset(&flow.app, 0, sizeof(flow.app));
    flow.app.protocol = (AppProtocol)99;
    output_print_flow_app_event(&flow);
}

int main(void) {
    test_output_print_packet_app_accepts_protocols();
    test_output_print_flow_app_event_accepts_flow();
    test_output_escapes_terminal_control_bytes();
    test_output_print_packet_app_handles_optional_fields();
    test_output_print_flow_app_event_handles_all_protocols();

    printf("All output tests passed.\n");

    return 0;
}
