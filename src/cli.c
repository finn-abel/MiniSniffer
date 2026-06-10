#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli.h"

static void print_usage(FILE *stream, const char *program_name) {
    const char *name = program_name == NULL ? "PacketScope" : program_name;

    /* Keep usage text in one place so errors and --help stay consistent. */
    fprintf(stream, "Usage: %s [--help] [--interface <name>] [--count <number>]\n", name);
    fprintf(stream, "       [--protocol <tcp|udp|icmp|other>] [--port <number>]\n");
    fprintf(stream, "       [--host <ipv4>] [--payload] [--payload-bytes <number>]\n");
    fprintf(stream, "       [--payload-contains <text>] [--payload-hex <hex>] [--log <file>]\n");
    fprintf(stream, "       [--stats]\n");
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
    fprintf(stderr, "Error: host must be a valid IPv4 address.\n");
    print_usage(stderr, program_name);
    return 1;
}

static int fail_invalid_payload_bytes(const char *program_name) {
    fprintf(stderr,
            "Error: payload byte preview must be between 1 and %u.\n",
            (unsigned int)PACKETSCOPE_MAX_PAYLOAD_PREVIEW_BYTES);
    print_usage(stderr, program_name);
    return 1;
}

static int fail_invalid_payload_text(const char *program_name) {
    fprintf(stderr,
            "Error: payload text filter must be between 1 and %u bytes.\n",
            (unsigned int)PACKETSCOPE_MAX_PAYLOAD_PATTERN_BYTES);
    print_usage(stderr, program_name);
    return 1;
}

static int fail_invalid_payload_hex(const char *program_name) {
    fprintf(stderr,
            "Error: payload hex filter must contain 1 to %u bytes of hex.\n",
            (unsigned int)PACKETSCOPE_MAX_PAYLOAD_PATTERN_BYTES);
    print_usage(stderr, program_name);
    return 1;
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
static int parse_payload_hex_pattern(
    const char *text,
    unsigned char *bytes,
    size_t *byte_count
) {
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
            if (count >= PACKETSCOPE_MAX_PAYLOAD_PATTERN_BYTES) {
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
    const char *program_name = argc > 0 ? argv[0] : "PacketScope";
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

        /* Value options update AppConfig and advance past their argument. */
        if (strcmp(argv[i], "--interface") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--interface requires a value.");
            }
            if (copy_arg(config->interface_name,
                         sizeof(config->interface_name),
                         argv[i + 1]) != 0) {
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
            struct in_addr address;

            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--host requires a value.");
            }
            if (inet_pton(AF_INET, argv[i + 1], &address) != 1) {
                return fail_invalid_host(program_name);
            }
            if (copy_arg(config->filter_host,
                         sizeof(config->filter_host),
                         argv[i + 1]) != 0) {
                return fail_invalid_host(program_name);
            }
            config->filter_host_enabled = 1;
            i++;
        } else if (strcmp(argv[i], "--log") == 0) {
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--log requires a file path.");
            }
            if (copy_arg(config->log_path,
                         sizeof(config->log_path),
                         argv[i + 1]) != 0) {
                return fail_with_error(program_name, "log path is too long.");
            }
            config->logging_enabled = 1;
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
                preview_bytes > PACKETSCOPE_MAX_PAYLOAD_PREVIEW_BYTES) {
                return fail_invalid_payload_bytes(program_name);
            }
            config->payload_preview_bytes = (size_t)preview_bytes;
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
            if (length == 0 || length > PACKETSCOPE_MAX_PAYLOAD_PATTERN_BYTES) {
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
            if (parse_payload_hex_pattern(argv[i + 1],
                                          config->filter_payload_hex,
                                          &config->filter_payload_hex_length) != 0) {
                return fail_invalid_payload_hex(program_name);
            }
            config->filter_payload_hex_enabled = 1;
            i++;
        } else if (strcmp(argv[i], "--stats") == 0) {
            /* Boolean options toggle config state without consuming a value. */
            config->stats_mode = 1;
        } else {
            return fail_with_error(program_name, "unknown option.");
        }
    }

    return 0;
}
