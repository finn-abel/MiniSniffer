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
    fprintf(stream, "       [--host <ipv4>] [--log <file>] [--stats]\n");
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

int cli_parse_args(int argc, char **argv, AppConfig *config) {
    const char *program_name = argc > 0 ? argv[0] : "PacketScope";
    int i;

    if (config == NULL) {
        return fail_with_error(program_name, "internal configuration is unavailable.");
    }

    /* Parse only metadata-oriented options; capture behavior is added later. */
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
            /* copy_arg enforces the AppConfig char[16] IPv4 host buffer limit. */
            if (!has_value(argc, argv, i)) {
                return fail_with_error(program_name, "--host requires a value.");
            }
            if (copy_arg(config->filter_host,
                         sizeof(config->filter_host),
                         argv[i + 1]) != 0) {
                return fail_with_error(program_name, "host must fit in an IPv4 string buffer.");
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
        } else if (strcmp(argv[i], "--stats") == 0) {
            /* Boolean options toggle config state without consuming a value. */
            config->stats_mode = 1;
        } else {
            return fail_with_error(program_name, "unknown option.");
        }
    }

    return 0;
}
