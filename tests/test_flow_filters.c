#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "filters.h"

static PacketInfo make_packet(void) {
    PacketInfo packet;

    memset(&packet, 0, sizeof(packet));
    packet.protocol = PROTO_TCP;
    packet.has_ports = 1;
    packet.src_port = 50000;
    packet.dst_port = 443;
    snprintf(packet.src_ip, sizeof(packet.src_ip), "192.168.1.25");
    snprintf(packet.dst_ip, sizeof(packet.dst_ip), "93.184.216.34");
    return packet;
}

static AppInfo make_tls_flow_app(void) {
    AppInfo app;

    memset(&app, 0, sizeof(app));
    app.protocol = APP_PROTO_TLS;
    snprintf(app.tls_sni, sizeof(app.tls_sni), "example.com");
    snprintf(app.tls_alpn, sizeof(app.tls_alpn), "h2");
    return app;
}

static void test_app_filter_starts_matching_only_after_flow_classification(void) {
    AppConfig config;
    PacketInfo packet = make_packet();
    AppInfo flow_app = make_tls_flow_app();
    FilterContext context;

    config_init_defaults(&config);
    config.decode_app = true;
    config.reassemble = true;
    config.filter_tls_sni_enabled = true;
    snprintf(config.filter_tls_sni, sizeof(config.filter_tls_sni), "example.com");

    context.packet = &packet;
    context.packet_app = NULL;
    context.flow_app = NULL;
    context.flow_is_classified = false;
    assert(!filters_match(&config, &context));

    context.flow_app = &flow_app;
    context.flow_is_classified = false;
    assert(!filters_match(&config, &context));

    context.flow_is_classified = true;
    assert(filters_match(&config, &context));
}

int main(void) {
    test_app_filter_starts_matching_only_after_flow_classification();

    printf("All flow filter tests passed.\n");

    return 0;
}
