#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "logger.h"

static FILE *log_file = NULL;
static int payload_logging_enabled = 0;
static size_t payload_logging_limit = PACKETSCOPE_DEFAULT_PAYLOAD_PREVIEW_BYTES;

/*
 * Logging format is chosen before logger_open writes the header.
 * Payload columns are opt-in so existing CSV consumers keep the old schema.
 */
void logger_set_payload_logging(int enabled, size_t preview_limit) {
    payload_logging_enabled = enabled;
    payload_logging_limit = preview_limit;
    if (payload_logging_limit > PACKETSCOPE_MAX_PAYLOAD_PREVIEW_BYTES) {
        payload_logging_limit = PACKETSCOPE_MAX_PAYLOAD_PREVIEW_BYTES;
    }
}

/*
 * CSV payload hex is kept human-readable with spaces between bytes.
 * The caller wraps this field in quotes because spaces are intentional.
 */
static void write_payload_hex(FILE *file, const PacketInfo *info) {
    size_t limit;
    size_t i;

    if (info->has_payload == 0) {
        return;
    }

    limit = info->payload_preview_length;
    if (limit > payload_logging_limit) {
        limit = payload_logging_limit;
    }

    for (i = 0; i < limit; i++) {
        fprintf(file, "%02x", info->payload_preview[i]);
        if (i + 1 < limit) {
            fprintf(file, " ");
        }
    }
}

/*
 * CSV payload ASCII converts non-printable bytes to dots and doubles quotes
 * according to CSV escaping rules.
 */
static void write_payload_ascii(FILE *file, const PacketInfo *info) {
    size_t limit;
    size_t i;

    if (info->has_payload == 0) {
        return;
    }

    limit = info->payload_preview_length;
    if (limit > payload_logging_limit) {
        limit = payload_logging_limit;
    }

    for (i = 0; i < limit; i++) {
        unsigned char value = info->payload_preview[i];

        /* Inside a quoted CSV field, a literal quote is represented as "". */
        if (value == '"') {
            fputc('"', file);
        }
        fputc(value >= 32 && value <= 126 ? value : '.', file);
    }
}

/*
 * Opens a fresh CSV log file and writes the header immediately.
 * Reopening logging closes any previous file first.
 */
int logger_open(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return 1;
    }

    logger_close();
    log_file = fopen(path, "w");
    if (log_file == NULL) {
        fprintf(stderr, "Error: cannot open log file '%s': %s\n", path, strerror(errno));
        return 1;
    }

    if (payload_logging_enabled != 0) {
        /* Payload logging appends preview fields to the base packet schema. */
        if (fprintf(log_file,
                    "packet_number,protocol,src_ip,src_port,dst_ip,dst_port,size,payload_length,payload_hex,payload_ascii\n") < 0) {
            fprintf(stderr, "Error: failed to write CSV header to '%s'.\n", path);
            logger_close();
            return 1;
        }

        return 0;
    }

    if (fprintf(log_file, "packet_number,protocol,src_ip,src_port,dst_ip,dst_port,size\n") < 0) {
        fprintf(stderr, "Error: failed to write CSV header to '%s'.\n", path);
        logger_close();
        return 1;
    }

    return 0;
}

/*
 * Writes one displayed packet row.
 * Packets without transport ports leave the src_port and dst_port fields empty.
 */
void logger_write(const PacketInfo *info) {
    if (log_file == NULL || info == NULL) {
        return;
    }

    if (payload_logging_enabled != 0) {
        /*
         * Build the row in small pieces so portless packets can leave the two
         * port fields empty while still sharing the payload column handling.
         */
        if (fprintf(log_file,
                    "%u,%s,%s,",
                    info->packet_number,
                    protocol_to_string(info->protocol),
                    info->src_ip) < 0) {
            fprintf(stderr, "Error: failed to write packet row to CSV log.\n");
            return;
        }

        if (info->has_ports != 0) {
            fprintf(log_file, "%u,%s,%u,",
                    (unsigned int)info->src_port,
                    info->dst_ip,
                    (unsigned int)info->dst_port);
        } else {
            fprintf(log_file, ",%s,,", info->dst_ip);
        }

        /* Quote payload preview fields so spaces and punctuation remain intact. */
        fprintf(log_file, "%zu,%zu,\"", info->size, info->payload_length);
        write_payload_hex(log_file, info);
        fprintf(log_file, "\",\"");
        write_payload_ascii(log_file, info);
        fprintf(log_file, "\"\n");
        return;
    }

    if (info->has_ports != 0) {
        if (fprintf(log_file,
                    "%u,%s,%s,%u,%s,%u,%zu\n",
                    info->packet_number,
                    protocol_to_string(info->protocol),
                    info->src_ip,
                    (unsigned int)info->src_port,
                    info->dst_ip,
                    (unsigned int)info->dst_port,
                    info->size) < 0) {
            fprintf(stderr, "Error: failed to write packet row to CSV log.\n");
        }
        return;
    }

    if (fprintf(log_file,
                "%u,%s,%s,,%s,,%zu\n",
                info->packet_number,
                protocol_to_string(info->protocol),
                info->src_ip,
                info->dst_ip,
                info->size) < 0) {
        fprintf(stderr, "Error: failed to write packet row to CSV log.\n");
    }
}

/*
 * Closes the active log file and resets module state.
 */
void logger_close(void) {
    if (log_file != NULL) {
        if (fclose(log_file) != 0) {
            fprintf(stderr, "Error: failed to close CSV log cleanly.\n");
        }
        log_file = NULL;
    }
}
