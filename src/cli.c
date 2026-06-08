#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli.h"

void cli_print_usage(const char *program_name) {
    const char *name = program_name == NULL ? "PacketScope" : program_name;

    /* Keep usage text in one place so errors and --help stay consistent. */
    printf("Usage: %s [--help] [--interface <name>] [--count <number>]\n", name);
    printf("       [--protocol <tcp|udp|icmp|other>] [--port <number>]\n");
    printf("       [--host <ipv4>] [--log <file>] [--stats]\n");
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
 * All parse failures report the same usage text and return a non-zero status.
 */
static int fail_with_usage(const char *program_name) {
    cli_print_usage(program_name);
    return 1;
}

int cli_parse_args(int argc, char **argv, AppConfig *config) {
    const char *program_name = argc > 0 ? argv[0] : "PacketScope";
    int i;

    if (config == NULL) {
        return fail_with_usage(program_name);
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
            if (!has_value(argc, argv, i) ||
                copy_arg(config->interface_name,
                         sizeof(config->interface_name),
                         argv[i + 1]) != 0) {
                return fail_with_usage(program_name);
            }
            i++;
        } else if (strcmp(argv[i], "--count") == 0) {
            if (!has_value(argc, argv, i) ||
                parse_positive_int(argv[i + 1], &config->max_packets) != 0) {
                return fail_with_usage(program_name);
            }
            i++;
        } else if (strcmp(argv[i], "--protocol") == 0) {
            if (!has_value(argc, argv, i) ||
                protocol_from_string(argv[i + 1], &config->filter_protocol) != 0) {
                return fail_with_usage(program_name);
            }
            config->filter_protocol_enabled = 1;
            i++;
        } else if (strcmp(argv[i], "--port") == 0) {
            int port;

            /* AppConfig stores ports as uint16_t, so reject values above 65535. */
            if (!has_value(argc, argv, i) ||
                parse_positive_int(argv[i + 1], &port) != 0 ||
                port > 65535) {
                return fail_with_usage(program_name);
            }
            config->filter_port_enabled = 1;
            config->filter_port = (uint16_t)port;
            i++;
        } else if (strcmp(argv[i], "--host") == 0) {
            if (!has_value(argc, argv, i) ||
                copy_arg(config->filter_host,
                         sizeof(config->filter_host),
                         argv[i + 1]) != 0) {
                return fail_with_usage(program_name);
            }
            config->filter_host_enabled = 1;
            i++;
        } else if (strcmp(argv[i], "--log") == 0) {
            if (!has_value(argc, argv, i) ||
                copy_arg(config->log_path,
                         sizeof(config->log_path),
                         argv[i + 1]) != 0) {
                return fail_with_usage(program_name);
            }
            config->logging_enabled = 1;
            i++;
        } else if (strcmp(argv[i], "--stats") == 0) {
            /* Boolean options toggle config state without consuming a value. */
            config->stats_mode = 1;
        } else {
            return fail_with_usage(program_name);
        }
    }

    return 0;
}
