#include <stdio.h>
#include <string.h>

#include "capture.h"
#include "cli.h"
#include "config.h"
#include "stats.h"

static int args_requested_help(int argc, char **argv) {
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            return 1;
        }
    }

    return 0;
}

static void print_startup_summary(const AppConfig *config) {
    if (config == NULL || config->quiet || config->json_output) {
        return;
    }

    printf("MiniSniffer starting...\n");
    printf("Interface: %s\n",
           config->interface_name[0] == '\0' ? "default" : config->interface_name);
    if (config->max_packets == 0) {
        printf("Max packets: unlimited\n");
    } else {
        printf("Max packets: %d\n", config->max_packets);
    }

    if (!config->verbose) {
        return;
    }

    printf("Stats mode: %s\n", config->stats_mode != 0 ? "enabled" : "disabled");
    printf("App decoding: %s\n", config->decode_app ? "enabled" : "disabled");
    printf("TCP reassembly: %s\n", config->reassemble ? "enabled" : "disabled");
    printf("Payload decode cap: %zu bytes\n", config->payload_decode_bytes);
    printf("Max flows: %zu\n", config->max_flows);
    printf("Stream buffer cap: %zu bytes\n", config->stream_buffer_bytes);
    printf("Flow timeout: %u seconds\n", (unsigned int)config->flow_timeout_seconds);

    if (config->filter_protocol_enabled != 0) {
        printf("Protocol filter: %s\n", protocol_to_string(config->filter_protocol));
    }
    if (config->filter_port_enabled != 0) {
        printf("Port filter: %u\n", (unsigned int)config->filter_port);
    }
    if (config->filter_host_enabled != 0) {
        printf("Host filter: %s\n", config->filter_host);
    }
    if (config->filter_payload_text_enabled != 0) {
        printf("Payload text filter: %zu bytes\n", config->filter_payload_text_length);
    }
    if (config->filter_payload_hex_enabled != 0) {
        printf("Payload hex filter: %zu bytes\n", config->filter_payload_hex_length);
    }
    if (config->payload_display_enabled != 0) {
        printf("Payload preview: %zu bytes\n", config->payload_preview_bytes);
    }
    if (config->filter_app_enabled) {
        printf("App filter: %s\n", config->filter_app_protocol == APP_PROTO_HTTP  ? "http"
                                   : config->filter_app_protocol == APP_PROTO_DNS ? "dns"
                                                                                  : "tls");
    }
    if (config->filter_http_host_enabled) {
        printf("HTTP host filter: %s\n", config->filter_http_host);
    }
    if (config->filter_http_method_enabled) {
        printf("HTTP method filter: %s\n", config->filter_http_method);
    }
    if (config->filter_dns_query_enabled) {
        printf("DNS query filter: %s\n", config->filter_dns_query);
    }
    if (config->filter_dns_type_enabled) {
        printf("DNS type filter: %u\n", (unsigned int)config->filter_dns_type);
    }
    if (config->filter_tls_sni_enabled) {
        printf("TLS SNI filter: %s\n", config->filter_tls_sni);
    }
    if (config->filter_tls_alpn_enabled) {
        printf("TLS ALPN filter: %s\n", config->filter_tls_alpn);
    }
    if (config->logging_enabled != 0) {
        printf("Log file: %s\n", config->log_path);
    }
}

int main(int argc, char **argv) {
    AppConfig config;
    PacketStats stats;
    int capture_result;

    /* Start from safe defaults before applying CLI options. */
    config_init_defaults(&config);
    if (cli_parse_args(argc, argv, &config) != 0) {
        return 1;
    }
    if (args_requested_help(argc, argv)) {
        return 0;
    }
    if (config.version_requested) {
        printf("MiniSniffer %s\n", MINISNIFFER_VERSION);
        return 0;
    }
    if (config.list_interfaces) {
        return capture_list_interfaces(stdout);
    }

    stats_init(&stats);

    print_startup_summary(&config);

    capture_result = capture_start(&config, &stats);

    if (config.stats_mode != 0 && !config.json_output) {
        stats_print(&stats);
    }

    return capture_result;
}
