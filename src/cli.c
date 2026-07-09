#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli.h"

static void print_usage(FILE *stream, const char *program_name) {
    const char *name = program_name == NULL ? "MiniSniffer" : program_name;

    /* Keep usage text in one place so errors and --help stay consistent. */
    fprintf(stream, "Usage: %s [--help] [--version] [--list-interfaces] [--interface <name>]\n",
            name);
    fprintf(stream, "       [--count <number>] [--quiet] [--verbose] [--no-color]\n");
    fprintf(stream, "       [--protocol <tcp|udp|icmp|other>] [--port <number>]\n");
    fprintf(stream, "       [--host <ip>] [--payload] [--payload-bytes <number>]\n");
    fprintf(stream, "       [--payload-decode-bytes <number>] [--domain-match <mode>]\n");
    fprintf(stream, "       [--payload-contains <text>] [--payload-hex <hex>] [--log <file>]\n");
    fprintf(stream, "       [--read <file.pcap>] [--write <file.pcap>]\n");
    fprintf(stream, "       [--json] [--flush-log <always|line|exit>]\n");
    fprintf(stream, "       [--decode-app] [--reassemble] [--max-flows <number>]\n");
    fprintf(stream, "       [--stream-buffer-bytes <number>] [--flow-timeout <seconds>]\n");
    fprintf(stream,
            "       [--app <http|dns|tls>] [--http-host <host>] [--http-method <method>]\n");
    fprintf(stream, "       [--dns-query <name>] [--dns-type <type>] [--tls-sni <host>]\n");
    fprintf(stream, "       [--tls-alpn <protocol>] [--stats]\n");
}

void cli_print_usage(const char *program_name) {
    print_usage(stdout, program_name);
}

/*
 * Options that require a value must have another argv entry after the flag.
 * A following token that starts with "--" is treated as another flag, not a value.
 */
static int has_value(int argc, char **argv, int index) {
    return index + 1 < argc && strncmp(argv[index + 1], "--", 2) != 0;
}

/*
 * Parse positive decimal integers for numeric CLI options.
 * Reject empty strings, partial parses, zero, negatives, overflow, and junk suffixes.
 */
static int parse_positive_int(const char *text, int *value) {
    char *end = NULL;
    long parsed;

    if (text == NULL || value == NULL || text[0] == '\0') {
        return 1;
    }

    errno = 0;
    parsed = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed <= 0 || parsed > INT_MAX) {
        return 1;
    }

    *value = (int)parsed;
    return 0;
}

/*
 * Parse positive decimal size values for bounded future app/flow settings.
 * Reject empty strings, partial parses, zero, negatives, overflow, and junk suffixes.
 */
static int parse_positive_size(const char *text, size_t *value) {
    char *end = NULL;
    unsigned long long parsed;

    if (text == NULL || value == NULL || text[0] == '\0' || text[0] == '-') {
        return 1;
    }

    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed == 0 ||
        parsed > (unsigned long long)SIZE_MAX) {
        return 1;
    }

    *value = (size_t)parsed;
    return 0;
}

static int parse_positive_uint32(const char *text, uint32_t *value) {
    size_t parsed;

    if (parse_positive_size(text, &parsed) != 0 || parsed > UINT32_MAX) {
        return 1;
    }

    *value = (uint32_t)parsed;
    return 0;
}

/*
 * Copy a CLI string into a fixed-size AppConfig buffer.
 * The destination must have room for the whole value and the null terminator.
 */
static int copy_arg(char *destination, size_t destination_size, const char *value) {
    size_t length;

    if (destination == NULL || value == NULL || destination_size == 0) {
        return 1;
    }

    length = strlen(value);
    if (length >= destination_size) {
        return 1;
    }

    memcpy(destination, value, length + 1);
    return 0;
}

/*
 * All parse failures report a specific error, then show usage for recovery.
 */
static int fail_with_error(const char *program_name, const char *message) {
    fprintf(stderr, "Error: %s\n", message);
    print_usage(stderr, program_name);
    return 1;
}

static int fail_invalid_protocol(const char *program_name, const char *value) {
    fprintf(stderr, "Error: invalid protocol: %s.\n", value);
    print_usage(stderr, program_name);
    return 1;
}

static int fail_invalid_port(const char *program_name) {
    fprintf(stderr, "Error: port must be between 1 and 65535.\n");
    print_usage(stderr, program_name);
    return 1;
}

static int fail_invalid_host(const char *program_name) {
    fprintf(stderr, "Error: host must be a valid IPv4 or IPv6 address.\n");
    print_usage(stderr, program_name);
    return 1;
}

static int fail_invalid_payload_bytes(const char *program_name) {
    fprintf(stderr, "Error: payload byte preview must be between 1 and %u.\n",
            (unsigned int)MINISNIFFER_MAX_PAYLOAD_PREVIEW_BYTES);
    print_usage(stderr, program_name);
    return 1;
}

static int fail_invalid_payload_decode_bytes(const char *program_name) {
    fprintf(stderr, "Error: payload decode bytes must be between 1 and %u.\n",
            (unsigned int)MINISNIFFER_MAX_PAYLOAD_DECODE_BYTES);
    print_usage(stderr, program_name);
    return 1;
}

static int fail_invalid_payload_text(const char *program_name) {
    fprintf(stderr, "Error: payload text filter must be between 1 and %u bytes.\n",
            (unsigned int)MINISNIFFER_MAX_PAYLOAD_PATTERN_BYTES);
    print_usage(stderr, program_name);
    return 1;
}

static int fail_invalid_payload_hex(const char *program_name) {
    fprintf(stderr, "Error: payload hex filter must contain 1 to %u bytes of hex.\n",
            (unsigned int)MINISNIFFER_MAX_PAYLOAD_PATTERN_BYTES);
    print_usage(stderr, program_name);
    return 1;
}

static int fail_invalid_app(const char *program_name, const char *value) {
    fprintf(stderr, "Error: invalid app protocol: %s.\n", value);
    print_usage(stderr, program_name);
    return 1;
}

static int fail_invalid_dns_type(const char *program_name, const char *value) {
    fprintf(stderr, "Error: invalid DNS type: %s.\n", value);
    print_usage(stderr, program_name);
    return 1;
}

static int fail_invalid_positive_size(const char *program_name, const char *option_name) {
    fprintf(stderr, "Error: %s must be a positive integer.\n", option_name);
    print_usage(stderr, program_name);
    return 1;
}

static int parse_log_flush_mode(const char *text, LogFlushMode *mode) {
    if (text == NULL || mode == NULL) {
        return 1;
    }
    if (strcmp(text, "always") == 0) {
        *mode = LOG_FLUSH_ALWAYS;
        return 0;
    }
    if (strcmp(text, "line") == 0) {
        *mode = LOG_FLUSH_LINE;
        return 0;
    }
    if (strcmp(text, "exit") == 0) {
        *mode = LOG_FLUSH_EXIT;
        return 0;
    }

    return 1;
}

/*
 * App protocol names are lowercase on the CLI to match future app filter names
 * and CSV app_protocol values.
 */
static int parse_app_protocol(const char *text, AppProtocol *protocol) {
    if (text == NULL || protocol == NULL) {
        return 1;
    }
    if (strcmp(text, "http") == 0) {
        *protocol = APP_PROTO_HTTP;
        return 0;
    }
    if (strcmp(text, "dns") == 0) {
        *protocol = APP_PROTO_DNS;
        return 0;
    }
    if (strcmp(text, "tls") == 0) {
        *protocol = APP_PROTO_TLS;
        return 0;
    }

    return 1;
}

static int parse_domain_match_mode(const char *text, DomainMatchMode *mode) {
    if (text == NULL || mode == NULL) {
        return 1;
    }
    if (strcmp(text, "normalized") == 0) {
        *mode = DOMAIN_MATCH_NORMALIZED;
        return 0;
    }
    if (strcmp(text, "exact") == 0) {
        *mode = DOMAIN_MATCH_EXACT;
        return 0;
    }
    if (strcmp(text, "idna") == 0) {
#ifdef MINISNIFFER_WITH_LIBIDN2
        *mode = DOMAIN_MATCH_IDNA;
        return 0;
#else
        return 2;
#endif
    }

    return 1;
}

/*
 * DNS type filters store numeric type codes in config. Common names are accepted
 * for usability while numeric values keep matching independent of display text.
 */
static int parse_dns_type(const char *text, uint16_t *type) {
    int numeric_type;

    if (text == NULL || type == NULL) {
        return 1;
    }
    if (strcmp(text, "A") == 0 || strcmp(text, "a") == 0) {
        *type = 1;
        return 0;
    }
    if (strcmp(text, "NS") == 0 || strcmp(text, "ns") == 0) {
        *type = 2;
        return 0;
    }
    if (strcmp(text, "CNAME") == 0 || strcmp(text, "cname") == 0) {
        *type = 5;
        return 0;
    }
    if (strcmp(text, "AAAA") == 0 || strcmp(text, "aaaa") == 0) {
        *type = 28;
        return 0;
    }
    if (parse_positive_int(text, &numeric_type) != 0 || numeric_type > 65535) {
        return 1;
    }

    *type = (uint16_t)numeric_type;
    return 0;
}

static int parse_ip_host(const char *text, char *destination, size_t destination_size) {
    struct in_addr address4;
    struct in6_addr address6;
    int family;
    const void *address;

    if (text == NULL || destination == NULL || destination_size == 0) {
        return 1;
    }
    if (inet_pton(AF_INET, text, &address4) == 1) {
        family = AF_INET;
        address = &address4;
    } else if (inet_pton(AF_INET6, text, &address6) == 1) {
        family = AF_INET6;
        address = &address6;
    } else {
        return 1;
    }

    return inet_ntop(family, address, destination, destination_size) == NULL ? 1 : 0;
}

/*
 * Convert one hexadecimal character into its numeric nibble value.
 * The payload hex parser accepts both upper and lower case input.
 */
static int hex_value(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }

    return -1;
}

/*
 * Parse CLI hex patterns into raw bytes for binary-safe payload matching.
 * Separators are accepted for readability, so "47 45 54", "47:45:54",
 * and "47-45-54" all produce the same three bytes.
 */
static int parse_payload_hex_pattern(const char *text, unsigned char *bytes, size_t *byte_count) {
    int high_nibble = -1;
    size_t count = 0;

    if (text == NULL || bytes == NULL || byte_count == NULL || text[0] == '\0') {
        return 1;
    }

    while (*text != '\0') {
        int value;

        /*
         * Ignore separators between bytes. They are not allowed to split a
         * single nibble from its pair because odd nibble counts fail below.
         */
        if (isspace((unsigned char)*text) || *text == ':' || *text == '-') {
            text++;
            continue;
        }

        value = hex_value(*text);
        if (value < 0) {
            return 1;
        }

        if (high_nibble < 0) {
            /* Store the first nibble until the second nibble completes a byte. */
            high_nibble = value;
        } else {
            if (count >= MINISNIFFER_MAX_PAYLOAD_PATTERN_BYTES) {
                return 1;
            }
            bytes[count] = (unsigned char)((high_nibble << 4) | value);
            count++;
            high_nibble = -1;
        }

        text++;
    }

    if (high_nibble >= 0 || count == 0) {
        /* Reject odd numbers of hex digits and separator-only strings. */
        return 1;
    }

    *byte_count = count;
    return 0;
}

int cli_parse_args(int argc, char **argv, AppConfig *config) {
    const char *program_name = argc > 0 ? argv[0] : "MiniSniffer";
    bool max_flows_was_set = false;
    bool stream_buffer_was_set = false;
    bool flow_timeout_was_set = false;
    int i;

    if (config == NULL) {
        return fail_with_error(program_name, "internal configuration is unavailable.");
    }

    /* Parse CLI options into the runtime configuration used by capture. */
    for (i = 1; i < argc; i++) {
        /* --help is terminal: print usage and stop parsing. */
        if (strcmp(argv[i], "--help") == 0) {
            cli_print_usage(program_name);
            return 0;
        }

        if (strcmp(argv[i], "--version") == 0) {
            config->version_requested = true;
        } else if (strcmp(argv[i], "--list-interfaces") == 0) {
            config->list_interfaces = true;
        } else if (strcmp(argv[i], "--quiet") == 0) {
            config->quiet = true;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            config->verbose = true;
        } else if (strcmp(argv[i], "--no-color") == 0) {
            config->color_enabled = false;
        } else if (strcmp(argv[i], "--json") == 0) {
            config->json_output = true;
            /* Value options update AppConfig and advance past their argument. */
        } else if (strcmp(argv[i], "--interface") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--interface requires a value.");
            }
            if (copy_arg(config->interface_name, sizeof(config->interface_name), argv[i + 1]) !=
                0) {
                return fail_with_error(program_name, "interface name is too long.");
            }
            i++;
        } else if (strcmp(argv[i], "--count") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--count requires a value.");
            }
            if (parse_positive_int(argv[i + 1], &config->max_packets) != 0) {
                return fail_with_error(program_name, "count must be a positive integer.");
            }
            i++;
        } else if (strcmp(argv[i], "--protocol") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--protocol requires a value.");
            }
            if (protocol_from_string(argv[i + 1], &config->filter_protocol) != 0) {
                return fail_invalid_protocol(program_name, argv[i + 1]);
            }
            config->filter_protocol_enabled = 1;
            i++;
        } else if (strcmp(argv[i], "--port") == 0) {
            int port;

            /* AppConfig stores ports as uint16_t, so reject values above 65535. */
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--port requires a value.");
            }
            if (parse_positive_int(argv[i + 1], &port) != 0 || port > 65535) {
                return fail_invalid_port(program_name);
            }
            config->filter_port_enabled = 1;
            config->filter_port = (uint16_t)port;
            i++;
        } else if (strcmp(argv[i], "--host") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--host requires a value.");
            }
            if (parse_ip_host(argv[i + 1], config->filter_host, sizeof(config->filter_host)) !=
                0) {
                return fail_invalid_host(program_name);
            }
            config->filter_host_enabled = 1;
            i++;
        } else if (strcmp(argv[i], "--log") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--log requires a file path.");
            }
            if (copy_arg(config->log_path, sizeof(config->log_path), argv[i + 1]) != 0) {
                return fail_with_error(program_name, "log path is too long.");
            }
            config->logging_enabled = 1;
            i++;
        } else if (strcmp(argv[i], "--read") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--read requires a file path.");
            }
            if (copy_arg(config->read_path, sizeof(config->read_path), argv[i + 1]) != 0) {
                return fail_with_error(program_name, "read path is too long.");
            }
            config->read_path_enabled = true;
            i++;
        } else if (strcmp(argv[i], "--write") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--write requires a file path.");
            }
            if (copy_arg(config->write_path, sizeof(config->write_path), argv[i + 1]) != 0) {
                return fail_with_error(program_name, "write path is too long.");
            }
            config->write_path_enabled = true;
            i++;
        } else if (strcmp(argv[i], "--flush-log") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--flush-log requires a value.");
            }
            if (parse_log_flush_mode(argv[i + 1], &config->log_flush_mode) != 0) {
                return fail_with_error(program_name, "--flush-log must be always, line, or exit.");
            }
            i++;
        } else if (strcmp(argv[i], "--payload") == 0) {
            /* Display is independent from filtering; filters can run silently. */
            config->payload_display_enabled = 1;
        } else if (strcmp(argv[i], "--payload-bytes") == 0) {
            int preview_bytes;

            /*
             * Keep previews bounded so printing/logging cannot dump arbitrarily
             * large packet bodies.
             */
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--payload-bytes requires a value.");
            }
            if (parse_positive_int(argv[i + 1], &preview_bytes) != 0 ||
                preview_bytes > MINISNIFFER_MAX_PAYLOAD_PREVIEW_BYTES) {
                return fail_invalid_payload_bytes(program_name);
            }
            config->payload_preview_bytes = (size_t)preview_bytes;
            i++;
        } else if (strcmp(argv[i], "--payload-decode-bytes") == 0) {
            size_t decode_bytes;

            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--payload-decode-bytes requires a value.");
            }
            if (parse_positive_size(argv[i + 1], &decode_bytes) != 0 ||
                decode_bytes > MINISNIFFER_MAX_PAYLOAD_DECODE_BYTES) {
                return fail_invalid_payload_decode_bytes(program_name);
            }
            config->payload_decode_bytes = decode_bytes;
            i++;
        } else if (strcmp(argv[i], "--domain-match") == 0) {
            int parse_result;

            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--domain-match requires a value.");
            }
            parse_result = parse_domain_match_mode(argv[i + 1], &config->domain_match_mode);
            if (parse_result == 2) {
                return fail_with_error(program_name,
                                       "--domain-match idna requires WITH_LIBIDN2=1.");
            }
            if (parse_result != 0) {
                return fail_with_error(program_name,
                                       "--domain-match must be normalized, exact, or idna.");
            }
            i++;
        } else if (strcmp(argv[i], "--payload-contains") == 0) {
            size_t length;

            /*
             * Store the text as bytes, not as a C string. Payloads can be
             * binary, so later matching uses explicit lengths.
             */
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--payload-contains requires a value.");
            }

            length = strlen(argv[i + 1]);
            if (length == 0 || length > MINISNIFFER_MAX_PAYLOAD_PATTERN_BYTES) {
                return fail_invalid_payload_text(program_name);
            }
            memcpy(config->filter_payload_text, argv[i + 1], length);
            config->filter_payload_text_length = length;
            config->filter_payload_text_enabled = 1;
            i++;
        } else if (strcmp(argv[i], "--payload-hex") == 0) {
            /* Hex filters let users match binary payload signatures directly. */
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--payload-hex requires a value.");
            }
            if (parse_payload_hex_pattern(argv[i + 1], config->filter_payload_hex,
                                          &config->filter_payload_hex_length) != 0) {
                return fail_invalid_payload_hex(program_name);
            }
            config->filter_payload_hex_enabled = 1;
            i++;
        } else if (strcmp(argv[i], "--decode-app") == 0) {
            config->decode_app = true;
        } else if (strcmp(argv[i], "--app") == 0) {
            /* App filters are parsed now but validated after all flags are read. */
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--app requires a value.");
            }
            if (parse_app_protocol(argv[i + 1], &config->filter_app_protocol) != 0) {
                return fail_invalid_app(program_name, argv[i + 1]);
            }
            config->filter_app_enabled = true;
            i++;
        } else if (strcmp(argv[i], "--http-host") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--http-host requires a value.");
            }
            if (copy_arg(config->filter_http_host, sizeof(config->filter_http_host), argv[i + 1]) !=
                0) {
                return fail_with_error(program_name, "HTTP host filter is too long.");
            }
            config->filter_http_host_enabled = true;
            i++;
        } else if (strcmp(argv[i], "--http-method") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--http-method requires a value.");
            }
            if (copy_arg(config->filter_http_method, sizeof(config->filter_http_method),
                         argv[i + 1]) != 0) {
                return fail_with_error(program_name, "HTTP method filter is too long.");
            }
            config->filter_http_method_enabled = true;
            i++;
        } else if (strcmp(argv[i], "--dns-query") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--dns-query requires a value.");
            }
            if (copy_arg(config->filter_dns_query, sizeof(config->filter_dns_query), argv[i + 1]) !=
                0) {
                return fail_with_error(program_name, "DNS query filter is too long.");
            }
            config->filter_dns_query_enabled = true;
            i++;
        } else if (strcmp(argv[i], "--dns-type") == 0) {
            /* Store DNS type as a number so A and 1 behave identically. */
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--dns-type requires a value.");
            }
            if (parse_dns_type(argv[i + 1], &config->filter_dns_type) != 0) {
                return fail_invalid_dns_type(program_name, argv[i + 1]);
            }
            config->filter_dns_type_enabled = true;
            i++;
        } else if (strcmp(argv[i], "--tls-sni") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--tls-sni requires a value.");
            }
            if (copy_arg(config->filter_tls_sni, sizeof(config->filter_tls_sni), argv[i + 1]) !=
                0) {
                return fail_with_error(program_name, "TLS SNI filter is too long.");
            }
            config->filter_tls_sni_enabled = true;
            i++;
        } else if (strcmp(argv[i], "--tls-alpn") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--tls-alpn requires a value.");
            }
            if (copy_arg(config->filter_tls_alpn, sizeof(config->filter_tls_alpn), argv[i + 1]) !=
                0) {
                return fail_with_error(program_name, "TLS ALPN filter is too long.");
            }
            config->filter_tls_alpn_enabled = true;
            i++;
        } else if (strcmp(argv[i], "--reassemble") == 0) {
            config->reassemble = true;
        } else if (strcmp(argv[i], "--max-flows") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--max-flows requires a value.");
            }
            if (parse_positive_size(argv[i + 1], &config->max_flows) != 0) {
                return fail_invalid_positive_size(program_name, "--max-flows");
            }
            max_flows_was_set = true;
            i++;
        } else if (strcmp(argv[i], "--stream-buffer-bytes") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--stream-buffer-bytes requires a value.");
            }
            if (parse_positive_size(argv[i + 1], &config->stream_buffer_bytes) != 0) {
                return fail_invalid_positive_size(program_name, "--stream-buffer-bytes");
            }
            stream_buffer_was_set = true;
            i++;
        } else if (strcmp(argv[i], "--flow-timeout") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--flow-timeout requires a value.");
            }
            if (parse_positive_uint32(argv[i + 1], &config->flow_timeout_seconds) != 0) {
                return fail_invalid_positive_size(program_name, "--flow-timeout");
            }
            flow_timeout_was_set = true;
            i++;
        } else if (strcmp(argv[i], "--stats") == 0) {
            /* Boolean options toggle config state without consuming a value. */
            config->stats_mode = 1;
        } else {
            return fail_with_error(program_name, "unknown option.");
        }
    }

    if (config->reassemble && !config->decode_app) {
        return fail_with_error(program_name, "--reassemble requires --decode-app.");
    }
    if (!config->reassemble &&
        (max_flows_was_set || stream_buffer_was_set || flow_timeout_was_set)) {
        return fail_with_error(program_name,
                               "stream buffer and flow table settings require --reassemble.");
    }
    if (config->reassemble && config->max_flows > MINISNIFFER_MAX_FLOWS) {
        return fail_with_error(program_name, "--max-flows exceeds the supported safety limit.");
    }
    if (config->reassemble && config->stream_buffer_bytes > MINISNIFFER_MAX_STREAM_BUFFER_BYTES) {
        return fail_with_error(program_name,
                               "--stream-buffer-bytes exceeds the supported safety limit.");
    }
    if (config->reassemble && config->max_flows > MINISNIFFER_MAX_TOTAL_REASSEMBLY_BYTES / 4 /
                                                      config->stream_buffer_bytes) {
        return fail_with_error(program_name,
                               "requested flow buffers exceed the aggregate memory limit.");
    }
    /*
     * App filters need decoded app metadata. Enforce this at parse time so a
     * mistyped command does not silently match no packets.
     */
    if (!config->decode_app &&
        (config->filter_app_enabled || config->filter_http_host_enabled ||
         config->filter_http_method_enabled || config->filter_dns_query_enabled ||
         config->filter_dns_type_enabled || config->filter_tls_sni_enabled ||
         config->filter_tls_alpn_enabled)) {
        return fail_with_error(program_name, "app filters require --decode-app.");
    }

    return 0;
}
