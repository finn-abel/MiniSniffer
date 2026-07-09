#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "cli.h"
#include "config.h"

static const char *EXPECTED_USAGE =
    "Usage: MiniSniffer [--help] [--version] [--list-interfaces] [--interface <name>]\n"
    "       [--count <number>] [--quiet] [--verbose] [--no-color]\n"
    "       [--protocol <tcp|udp|icmp|other>] [--port <number>]\n"
    "       [--host <ip>] [--payload] [--payload-bytes <number>]\n"
    "       [--payload-decode-bytes <number>] [--domain-match <mode>]\n"
    "       [--payload-contains <text>] [--payload-hex <hex>] [--log <file>]\n"
    "       [--read <file.pcap>] [--write <file.pcap>]\n"
    "       [--json] [--flush-log <always|line|exit>]\n"
    "       [--decode-app] [--reassemble] [--max-flows <number>]\n"
    "       [--stream-buffer-bytes <number>] [--flow-timeout <seconds>]\n"
    "       [--app <http|dns|tls>] [--http-host <host>] [--http-method <method>]\n"
    "       [--dns-query <name>] [--dns-type <type>] [--tls-sni <host>]\n"
    "       [--tls-alpn <protocol>] [--stats]\n";

typedef void (*CaptureFunction)(void *context);

typedef struct CliCaptureContext {
    int argc;
    char **argv;
    int result;
} CliCaptureContext;

static void capture_stream_output(int fd, FILE *stream, CaptureFunction function, void *context,
                                  char *buffer, size_t buffer_size) {
    FILE *capture;
    int saved_fd;
    size_t bytes_read;

    assert(buffer != NULL);
    assert(buffer_size > 0);

    capture = tmpfile();
    assert(capture != NULL);

    fflush(stream);
    saved_fd = dup(fd);
    assert(saved_fd >= 0);
    assert(dup2(fileno(capture), fd) >= 0);

    function(context);

    fflush(stream);
    assert(dup2(saved_fd, fd) >= 0);
    close(saved_fd);

    rewind(capture);
    bytes_read = fread(buffer, 1, buffer_size - 1, capture);
    buffer[bytes_read] = '\0';
    assert(!ferror(capture));
    fclose(capture);
}

static void call_cli_print_usage(void *context) {
    (void)context;
    cli_print_usage("MiniSniffer");
}

static void call_cli_print_usage_null(void *context) {
    (void)context;
    cli_print_usage(NULL);
}

static void call_cli_parse_args(void *context) {
    CliCaptureContext *capture = context;
    AppConfig config;

    config_init_defaults(&config);
    capture->result = cli_parse_args(capture->argc, capture->argv, &config);
}

static void test_cli_parse_args_accepts_no_args(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer"};

    config_init_defaults(&config);

    assert(cli_parse_args(1, argv, &config) == 0);
}

static void test_cli_parse_args_accepts_help(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--help"};

    config_init_defaults(&config);

    assert(cli_parse_args(2, argv, &config) == 0);
}

static void test_cli_parse_args_sets_interface_ux_flags(void) {
    AppConfig config;
    char *version[] = {"MiniSniffer", "--version"};
    char *list[] = {"MiniSniffer", "--list-interfaces"};
    char *quiet_verbose[] = {"MiniSniffer", "--quiet", "--verbose", "--no-color", "--json"};
    char *flush_always[] = {"MiniSniffer", "--flush-log", "always"};
    char *flush_exit[] = {"MiniSniffer", "--flush-log", "exit"};

    config_init_defaults(&config);
    assert(cli_parse_args(2, version, &config) == 0);
    assert(config.version_requested == true);

    config_init_defaults(&config);
    assert(cli_parse_args(2, list, &config) == 0);
    assert(config.list_interfaces == true);

    config_init_defaults(&config);
    assert(cli_parse_args(5, quiet_verbose, &config) == 0);
    assert(config.quiet == true);
    assert(config.verbose == true);
    assert(config.color_enabled == false);
    assert(config.json_output == true);

    config_init_defaults(&config);
    assert(cli_parse_args(3, flush_always, &config) == 0);
    assert(config.log_flush_mode == LOG_FLUSH_ALWAYS);

    config_init_defaults(&config);
    assert(cli_parse_args(3, flush_exit, &config) == 0);
    assert(config.log_flush_mode == LOG_FLUSH_EXIT);
}

static void test_cli_parse_args_sets_interface(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--interface", "en0"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(strcmp(config.interface_name, "en0") == 0);
}

static void test_cli_parse_args_sets_count(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--count", "10"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.max_packets == 10);
}

static void test_cli_parse_args_sets_protocol(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--protocol", "tcp"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.filter_protocol_enabled == 1);
    assert(config.filter_protocol == PROTO_TCP);
}

static void test_cli_parse_args_sets_port(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--port", "443"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.filter_port_enabled == 1);
    assert(config.filter_port == 443);
}

static void test_cli_parse_args_sets_host(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--host", "8.8.8.8"};
    char *ipv6[] = {"MiniSniffer", "--host", "2001:0db8:0000:0000:0000:0000:0000:0001"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.filter_host_enabled == 1);
    assert(strcmp(config.filter_host, "8.8.8.8") == 0);

    config_init_defaults(&config);
    assert(cli_parse_args(3, ipv6, &config) == 0);
    assert(config.filter_host_enabled == 1);
    assert(strcmp(config.filter_host, "2001:db8::1") == 0);
}

static void test_cli_parse_args_sets_log(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--log", "packets.csv"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.logging_enabled == 1);
    assert(strcmp(config.log_path, "packets.csv") == 0);
}

static void test_cli_parse_args_sets_offline_pcap_paths(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--read", "input.pcap", "--write", "filtered.pcap"};

    config_init_defaults(&config);

    assert(cli_parse_args(5, argv, &config) == 0);
    assert(config.read_path_enabled == true);
    assert(strcmp(config.read_path, "input.pcap") == 0);
    assert(config.write_path_enabled == true);
    assert(strcmp(config.write_path, "filtered.pcap") == 0);
}

static void test_cli_parse_args_sets_stats(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--stats"};

    config_init_defaults(&config);

    assert(cli_parse_args(2, argv, &config) == 0);
    assert(config.stats_mode == 1);
}

static void test_cli_parse_args_sets_payload_display(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--payload", "--payload-bytes", "32",
                    "--payload-decode-bytes", "4096"};

    config_init_defaults(&config);

    assert(cli_parse_args(6, argv, &config) == 0);
    assert(config.payload_display_enabled == 1);
    assert(config.payload_preview_bytes == 32);
    assert(config.payload_decode_bytes == 4096);
}

static void test_cli_parse_args_sets_payload_text_filter(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--payload-contains", "GET "};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.filter_payload_text_enabled == 1);
    assert(config.filter_payload_text_length == 4);
    assert(memcmp(config.filter_payload_text, "GET ", 4) == 0);
}

static void test_cli_parse_args_sets_payload_hex_filter(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--payload-hex", "47 45 54"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) == 0);
    assert(config.filter_payload_hex_enabled == 1);
    assert(config.filter_payload_hex_length == 3);
    assert(config.filter_payload_hex[0] == 0x47);
    assert(config.filter_payload_hex[1] == 0x45);
    assert(config.filter_payload_hex[2] == 0x54);
}

static void test_cli_parse_args_sets_app_decode_options(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--decode-app",   "--reassemble",
                    "--max-flows", "1024",           "--stream-buffer-bytes",
                    "32768",       "--flow-timeout", "30"};

    config_init_defaults(&config);

    assert(cli_parse_args(9, argv, &config) == 0);
    assert(config.decode_app == true);
    assert(config.reassemble == true);
    assert(config.max_flows == 1024);
    assert(config.stream_buffer_bytes == 32768);
    assert(config.flow_timeout_seconds == 30);
}

static void test_cli_parse_args_accepts_supported_app_examples(void) {
    AppConfig config;
    char *decode_app[] = {"MiniSniffer", "--decode-app"};
    char *app_dns[] = {"MiniSniffer", "--decode-app", "--app", "dns"};
    char *http_host[] = {"MiniSniffer", "--decode-app", "--app",
                         "http",        "--http-host",  "example.com"};
    char *tls_sni[] = {"MiniSniffer", "--decode-app", "--app", "tls", "--tls-sni", "example.com"};
    char *reassembled_tls_sni[] = {"MiniSniffer", "--decode-app", "--reassemble", "--tls-sni",
                                   "example.com"};
    char *stream_buffer[] = {"MiniSniffer", "--decode-app", "--reassemble", "--stream-buffer-bytes",
                             "65536"};

    config_init_defaults(&config);
    assert(cli_parse_args(2, decode_app, &config) == 0);
    assert(config.decode_app);

    config_init_defaults(&config);
    assert(cli_parse_args(4, app_dns, &config) == 0);
    assert(config.filter_app_protocol == APP_PROTO_DNS);

    config_init_defaults(&config);
    assert(cli_parse_args(6, http_host, &config) == 0);
    assert(config.filter_app_protocol == APP_PROTO_HTTP);
    assert(strcmp(config.filter_http_host, "example.com") == 0);

    config_init_defaults(&config);
    assert(cli_parse_args(6, tls_sni, &config) == 0);
    assert(config.filter_app_protocol == APP_PROTO_TLS);
    assert(strcmp(config.filter_tls_sni, "example.com") == 0);

    config_init_defaults(&config);
    assert(cli_parse_args(5, reassembled_tls_sni, &config) == 0);
    assert(config.reassemble);
    assert(strcmp(config.filter_tls_sni, "example.com") == 0);

    config_init_defaults(&config);
    assert(cli_parse_args(5, stream_buffer, &config) == 0);
    assert(config.reassemble);
    assert(config.stream_buffer_bytes == 65536);
}

static void test_cli_parse_args_sets_app_filters(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--decode-app", "--app",         "http",
                    "--http-host", "example.com",  "--http-method", "GET",
                    "--dns-query", "example.com",  "--dns-type",    "A",
                    "--tls-sni",   "example.com",  "--tls-alpn",    "h2"};

    config_init_defaults(&config);

    assert(cli_parse_args(16, argv, &config) == 0);
    assert(config.filter_app_enabled == true);
    assert(config.filter_app_protocol == APP_PROTO_HTTP);
    assert(config.filter_http_host_enabled == true);
    assert(strcmp(config.filter_http_host, "example.com") == 0);
    assert(config.filter_http_method_enabled == true);
    assert(strcmp(config.filter_http_method, "GET") == 0);
    assert(config.filter_dns_query_enabled == true);
    assert(strcmp(config.filter_dns_query, "example.com") == 0);
    assert(config.filter_dns_type_enabled == true);
    assert(config.filter_dns_type == 1);
    assert(config.filter_tls_sni_enabled == true);
    assert(strcmp(config.filter_tls_sni, "example.com") == 0);
    assert(config.filter_tls_alpn_enabled == true);
    assert(strcmp(config.filter_tls_alpn, "h2") == 0);

    config_init_defaults(&config);
    assert(cli_parse_args(4, (char *[]){"MiniSniffer", "--decode-app", "--domain-match", "exact"},
                          &config) == 0);
    assert(config.domain_match_mode == DOMAIN_MATCH_EXACT);
}

static void test_cli_parse_args_accepts_combined_filters(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--protocol", "tcp", "--port", "443", "--count", "10"};

    config_init_defaults(&config);

    assert(cli_parse_args(7, argv, &config) == 0);
    assert(config.filter_protocol_enabled == 1);
    assert(config.filter_protocol == PROTO_TCP);
    assert(config.filter_port_enabled == 1);
    assert(config.filter_port == 443);
    assert(config.max_packets == 10);
}

static void test_cli_parse_args_rejects_unknown_flag(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--badflag"};

    config_init_defaults(&config);

    assert(cli_parse_args(2, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_missing_value(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--interface"};

    config_init_defaults(&config);

    assert(cli_parse_args(2, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_fake_protocol(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--protocol", "fake"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_invalid_port(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--port", "99999"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_zero_count(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--count", "0"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_long_host(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--host", "2001:db8::12345"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_invalid_host(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--host", "999.1.1.1"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_invalid_payload_options(void) {
    AppConfig config;
    char *payload_bytes[] = {"MiniSniffer", "--payload-bytes", "999"};
    char *payload_decode_bytes[] = {"MiniSniffer", "--payload-decode-bytes", "999999"};
    char *payload_hex[] = {"MiniSniffer", "--payload-hex", "abc"};

    config_init_defaults(&config);
    assert(cli_parse_args(3, payload_bytes, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(3, payload_decode_bytes, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(3, payload_hex, &config) != 0);
}

static void test_cli_parse_args_rejects_invalid_app_decode_options(void) {
    AppConfig config;
    char *reassemble_without_decode[] = {"MiniSniffer", "--reassemble"};
    char *max_flows_zero[] = {"MiniSniffer", "--decode-app", "--reassemble", "--max-flows", "0"};
    char *stream_buffer_negative[] = {"MiniSniffer", "--decode-app", "--reassemble",
                                      "--stream-buffer-bytes", "-1"};
    char *flow_timeout_bad[] = {"MiniSniffer", "--decode-app", "--reassemble", "--flow-timeout",
                                "abc"};
    char *max_flows_without_reassemble[] = {"MiniSniffer", "--decode-app", "--max-flows", "10"};
    char *stream_buffer_without_reassemble[] = {"MiniSniffer", "--decode-app",
                                                "--stream-buffer-bytes", "1024"};
    char *flow_timeout_without_reassemble[] = {"MiniSniffer", "--decode-app", "--flow-timeout",
                                               "10"};
    char *max_flows_too_large[] = {"MiniSniffer", "--decode-app", "--reassemble", "--max-flows",
                                   "1025"};
    char *stream_buffer_too_large[] = {"MiniSniffer", "--decode-app", "--reassemble",
                                       "--stream-buffer-bytes", "1048577"};
    char *aggregate_memory_too_large[] = {"MiniSniffer", "--decode-app", "--reassemble",
                                          "--max-flows", "1024",         "--stream-buffer-bytes",
                                          "32769"};

    config_init_defaults(&config);
    assert(cli_parse_args(2, reassemble_without_decode, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(5, max_flows_zero, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(5, stream_buffer_negative, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(5, flow_timeout_bad, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(4, max_flows_without_reassemble, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(4, stream_buffer_without_reassemble, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(4, flow_timeout_without_reassemble, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(5, max_flows_too_large, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(5, stream_buffer_too_large, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(7, aggregate_memory_too_large, &config) != 0);
}

static void test_cli_parse_args_rejects_app_filters_without_decode_app(void) {
    AppConfig config;
    char *argv[] = {"MiniSniffer", "--app", "dns"};

    config_init_defaults(&config);

    assert(cli_parse_args(3, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_invalid_app_filters(void) {
    AppConfig config;
    char *bad_app[] = {"MiniSniffer", "--decode-app", "--app", "smtp"};
    char *bad_dns_type[] = {"MiniSniffer", "--decode-app", "--dns-type", "NOPE"};

    config_init_defaults(&config);
    assert(cli_parse_args(4, bad_app, &config) != 0);

    config_init_defaults(&config);
    assert(cli_parse_args(4, bad_dns_type, &config) != 0);
}

static void assert_cli_rejects(int argc, char **argv) {
    AppConfig config;

    config_init_defaults(&config);
    assert(cli_parse_args(argc, argv, &config) != 0);
}

static void test_cli_parse_args_rejects_all_missing_values(void) {
    char *count[] = {"MiniSniffer", "--count"};
    char *protocol[] = {"MiniSniffer", "--protocol"};
    char *port[] = {"MiniSniffer", "--port"};
    char *host[] = {"MiniSniffer", "--host"};
    char *log[] = {"MiniSniffer", "--log"};
    char *read_path[] = {"MiniSniffer", "--read"};
    char *write_path[] = {"MiniSniffer", "--write"};
    char *payload_bytes[] = {"MiniSniffer", "--payload-bytes"};
    char *payload_text[] = {"MiniSniffer", "--payload-contains"};
    char *payload_hex[] = {"MiniSniffer", "--payload-hex"};
    char *app[] = {"MiniSniffer", "--app"};
    char *http_host[] = {"MiniSniffer", "--http-host"};
    char *http_method[] = {"MiniSniffer", "--http-method"};
    char *dns_query[] = {"MiniSniffer", "--dns-query"};
    char *dns_type[] = {"MiniSniffer", "--dns-type"};
    char *tls_sni[] = {"MiniSniffer", "--tls-sni"};
    char *tls_alpn[] = {"MiniSniffer", "--tls-alpn"};
    char *max_flows[] = {"MiniSniffer", "--max-flows"};
    char *stream_buffer[] = {"MiniSniffer", "--stream-buffer-bytes"};
    char *flow_timeout[] = {"MiniSniffer", "--flow-timeout"};
    char *flush_log[] = {"MiniSniffer", "--flush-log"};
    char *payload_decode_bytes[] = {"MiniSniffer", "--payload-decode-bytes"};
    char *domain_match[] = {"MiniSniffer", "--domain-match"};

    assert_cli_rejects(2, count);
    assert_cli_rejects(2, protocol);
    assert_cli_rejects(2, port);
    assert_cli_rejects(2, host);
    assert_cli_rejects(2, log);
    assert_cli_rejects(2, read_path);
    assert_cli_rejects(2, write_path);
    assert_cli_rejects(2, payload_bytes);
    assert_cli_rejects(2, payload_text);
    assert_cli_rejects(2, payload_hex);
    assert_cli_rejects(2, app);
    assert_cli_rejects(2, http_host);
    assert_cli_rejects(2, http_method);
    assert_cli_rejects(2, dns_query);
    assert_cli_rejects(2, dns_type);
    assert_cli_rejects(2, tls_sni);
    assert_cli_rejects(2, tls_alpn);
    assert_cli_rejects(2, max_flows);
    assert_cli_rejects(2, stream_buffer);
    assert_cli_rejects(2, flow_timeout);
    assert_cli_rejects(2, flush_log);
    assert_cli_rejects(2, payload_decode_bytes);
    assert_cli_rejects(2, domain_match);
}

static void test_cli_parse_args_rejects_oversized_strings(void) {
    char long_value[300];
    char *interface[] = {"MiniSniffer", "--interface", long_value};
    char *log[] = {"MiniSniffer", "--log", long_value};
    char *read_path[] = {"MiniSniffer", "--read", long_value};
    char *write_path[] = {"MiniSniffer", "--write", long_value};
    char *payload_text[] = {"MiniSniffer", "--payload-contains", long_value};
    char *http_host[] = {"MiniSniffer", "--decode-app", "--http-host", long_value};
    char *http_method[] = {"MiniSniffer", "--decode-app", "--http-method", long_value};
    char *dns_query[] = {"MiniSniffer", "--decode-app", "--dns-query", long_value};
    char *tls_sni[] = {"MiniSniffer", "--decode-app", "--tls-sni", long_value};
    char *tls_alpn[] = {"MiniSniffer", "--decode-app", "--tls-alpn", long_value};

    memset(long_value, 'x', sizeof(long_value) - 1);
    long_value[sizeof(long_value) - 1] = '\0';
    assert_cli_rejects(3, interface);
    assert_cli_rejects(3, log);
    assert_cli_rejects(3, read_path);
    assert_cli_rejects(3, write_path);
    assert_cli_rejects(3, payload_text);
    assert_cli_rejects(4, http_host);
    assert_cli_rejects(4, http_method);
    assert_cli_rejects(4, dns_query);
    assert_cli_rejects(4, tls_sni);
    assert_cli_rejects(4, tls_alpn);
}

static void test_cli_parse_args_accepts_dns_types_and_uppercase_hex(void) {
    AppConfig config;
    char *dns_ns[] = {"MiniSniffer", "--decode-app", "--dns-type", "NS"};
    char *dns_cname[] = {"MiniSniffer", "--decode-app", "--dns-type", "CNAME"};
    char *dns_aaaa[] = {"MiniSniffer", "--decode-app", "--dns-type", "AAAA"};
    char *dns_numeric[] = {"MiniSniffer", "--decode-app", "--dns-type", "15"};
    char *payload_hex[] = {"MiniSniffer", "--payload-hex", "AF 0B"};

    config_init_defaults(&config);
    assert(cli_parse_args(4, dns_ns, &config) == 0);
    assert(config.filter_dns_type == 2);
    config_init_defaults(&config);
    assert(cli_parse_args(4, dns_cname, &config) == 0);
    assert(config.filter_dns_type == 5);
    config_init_defaults(&config);
    assert(cli_parse_args(4, dns_aaaa, &config) == 0);
    assert(config.filter_dns_type == 28);
    config_init_defaults(&config);
    assert(cli_parse_args(4, dns_numeric, &config) == 0);
    assert(config.filter_dns_type == 15);
    config_init_defaults(&config);
    assert(cli_parse_args(3, payload_hex, &config) == 0);
    assert(config.filter_payload_hex[0] == 0xaf);
    assert(config.filter_payload_hex[1] == 0x0b);
}

static void test_cli_parse_args_rejects_empty_and_overflow_values(void) {
    char *payload_text[] = {"MiniSniffer", "--payload-contains", ""};
    char *payload_hex[] = {"MiniSniffer", "--payload-hex", "GG"};
    char *count[] = {"MiniSniffer", "--count", "999999999999999999999999"};
    char *timeout[] = {"MiniSniffer", "--decode-app", "--reassemble", "--flow-timeout",
                       "4294967296"};
    char *flush_log[] = {"MiniSniffer", "--flush-log", "sometimes"};
    char *domain_match[] = {"MiniSniffer", "--domain-match", "sometimes"};
    char *domain_idna[] = {"MiniSniffer", "--domain-match", "idna"};

    assert_cli_rejects(3, payload_text);
    assert_cli_rejects(3, payload_hex);
    assert_cli_rejects(3, count);
    assert_cli_rejects(5, timeout);
    assert_cli_rejects(3, flush_log);
#ifndef MINISNIFFER_WITH_LIBIDN2
    assert_cli_rejects(3, domain_idna);
#endif
    assert_cli_rejects(3, domain_match);
    assert(cli_parse_args(1, (char *[]){"MiniSniffer"}, NULL) != 0);
}

static void test_cli_print_usage_matches_golden_output(void) {
    char output[1024];

    capture_stream_output(STDOUT_FILENO, stdout, call_cli_print_usage, NULL, output,
                          sizeof(output));
    TEST_ASSERT_STRING_EQUAL(output, EXPECTED_USAGE);
}

static void test_cli_parse_args_unknown_flag_matches_golden_error(void) {
    char output[2048];
    char *argv[] = {"MiniSniffer", "--badflag"};
    CliCaptureContext capture = {2, argv, 0};
    char expected[2048];

    snprintf(expected, sizeof(expected), "Error: unknown option.\n%s", EXPECTED_USAGE);
    capture_stream_output(STDERR_FILENO, stderr, call_cli_parse_args, &capture, output,
                          sizeof(output));

    assert(capture.result != 0);
    TEST_ASSERT_STRING_EQUAL(output, expected);
}

static void test_cli_parse_args_missing_value_matches_golden_error(void) {
    char output[2048];
    char *argv[] = {"MiniSniffer", "--interface"};
    CliCaptureContext capture = {2, argv, 0};
    char expected[2048];

    snprintf(expected, sizeof(expected), "Error: --interface requires a value.\n%s",
             EXPECTED_USAGE);
    capture_stream_output(STDERR_FILENO, stderr, call_cli_parse_args, &capture, output,
                          sizeof(output));

    assert(capture.result != 0);
    TEST_ASSERT_STRING_EQUAL(output, expected);
}

static void test_cli_print_usage_accepts_null_program_name(void) {
    char output[1024];

    capture_stream_output(STDOUT_FILENO, stdout, call_cli_print_usage_null, NULL, output,
                          sizeof(output));
    TEST_ASSERT_STRING_EQUAL(output, EXPECTED_USAGE);
}

int main(void) {
    test_cli_parse_args_accepts_no_args();
    test_cli_parse_args_accepts_help();
    test_cli_parse_args_sets_interface_ux_flags();
    test_cli_parse_args_sets_interface();
    test_cli_parse_args_sets_count();
    test_cli_parse_args_sets_protocol();
    test_cli_parse_args_sets_port();
    test_cli_parse_args_sets_host();
    test_cli_parse_args_sets_log();
    test_cli_parse_args_sets_offline_pcap_paths();
    test_cli_parse_args_sets_stats();
    test_cli_parse_args_sets_payload_display();
    test_cli_parse_args_sets_payload_text_filter();
    test_cli_parse_args_sets_payload_hex_filter();
    test_cli_parse_args_sets_app_decode_options();
    test_cli_parse_args_accepts_supported_app_examples();
    test_cli_parse_args_sets_app_filters();
    test_cli_parse_args_accepts_combined_filters();
    test_cli_parse_args_rejects_unknown_flag();
    test_cli_parse_args_rejects_missing_value();
    test_cli_parse_args_rejects_fake_protocol();
    test_cli_parse_args_rejects_invalid_port();
    test_cli_parse_args_rejects_zero_count();
    test_cli_parse_args_rejects_long_host();
    test_cli_parse_args_rejects_invalid_host();
    test_cli_parse_args_rejects_invalid_payload_options();
    test_cli_parse_args_rejects_invalid_app_decode_options();
    test_cli_parse_args_rejects_app_filters_without_decode_app();
    test_cli_parse_args_rejects_invalid_app_filters();
    test_cli_parse_args_rejects_all_missing_values();
    test_cli_parse_args_rejects_oversized_strings();
    test_cli_parse_args_accepts_dns_types_and_uppercase_hex();
    test_cli_parse_args_rejects_empty_and_overflow_values();
    test_cli_print_usage_matches_golden_output();
    test_cli_parse_args_unknown_flag_matches_golden_error();
    test_cli_parse_args_missing_value_matches_golden_error();
    test_cli_print_usage_accepts_null_program_name();

    printf("All cli tests passed.\n");

    return 0;
}
