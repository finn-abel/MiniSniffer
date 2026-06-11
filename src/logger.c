#include <stdbool.h>

#include "csv_logger.h"
#include "logger.h"

static bool payload_logging_enabled = false;
static size_t payload_logging_limit = MINISNIFFER_MAX_PAYLOAD_PREVIEW_BYTES;

/*
 * logger.c preserves the original packet CSV API while csv_logger.c owns the
 * newer schema-aware implementation.
 */
void logger_set_payload_logging(int enabled, size_t preview_limit) {
    payload_logging_enabled = enabled != 0;
    payload_logging_limit = preview_limit;
}

/*
 * Legacy logger calls always open without app columns.
 */
int logger_open(const char *path) {
    return csv_logger_open(path, false, payload_logging_enabled, payload_logging_limit);
}

void logger_write(const PacketInfo *info) {
    csv_logger_write_packet(info, NULL, "none");
}

void logger_close(void) {
    csv_logger_close();
}
