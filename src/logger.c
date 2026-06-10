#include <stdio.h>

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
        return 1;
    }

    fprintf(log_file, "packet_number,protocol,src_ip,src_port,dst_ip,dst_port,size\n");
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
        fprintf(log_file,
                "%u,%s,%s,%u,%s,%u,%zu\n",
                info->packet_number,
                protocol_to_string(info->protocol),
                info->src_ip,
                (unsigned int)info->src_port,
                info->dst_ip,
                (unsigned int)info->dst_port,
                info->size);
        return;
    }

    fprintf(log_file,
            "%u,%s,%s,,%s,,%zu\n",
            info->packet_number,
            protocol_to_string(info->protocol),
            info->src_ip,
            info->dst_ip,
            info->size);
}

/*
 * Closes the active log file and resets module state.
 */
void logger_close(void) {
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
}
