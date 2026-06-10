#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "logger.h"

static FILE *log_file = NULL;

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
