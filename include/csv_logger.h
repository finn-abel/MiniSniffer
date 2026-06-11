#ifndef CSV_LOGGER_H
#define CSV_LOGGER_H

#include <stdbool.h>

#include "common.h"

/*
 * Opens a CSV log with either the legacy packet schema or the stable app schema.
 * App-enabled logs use the same columns for packet and future flow metadata.
 */
int csv_logger_open(
    const char *path,
    bool app_columns_enabled,
    bool payload_columns_enabled,
    size_t payload_preview_limit
);

/*
 * Writes one displayed packet row.
 * app_source should be "packet", "flow", or "none" when app columns are enabled.
 */
void csv_logger_write_packet(
    const PacketInfo *packet,
    const AppInfo *app,
    const char *app_source
);

/*
 * Closes the active CSV file if one is open.
 */
void csv_logger_close(void);

#endif
