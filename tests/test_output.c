#include <stdio.h>
#include <string.h>

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

int main(void) {
    test_output_print_packet_app_accepts_protocols();
    test_output_print_flow_app_event_accepts_flow();

    printf("All output tests passed.\n");

    return 0;
}
