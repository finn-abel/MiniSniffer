#ifndef LOGGER_H
#define LOGGER_H

#include "common.h"

/*
 * Opens a CSV log file and writes the packet log header.
 * Returns 0 when the file is ready for packet rows.
 * Returns non-zero when the file cannot be opened.
 */
int logger_open(const char *path);

/*
 * Controls whether CSV logs include payload preview columns.
 */
void logger_set_payload_logging(int enabled, size_t preview_limit);

/*
 * Writes one displayed packet to the active CSV log.
 * If logging is not open, this function does nothing.
 */
void logger_write(const PacketInfo *info);

/*
 * Closes the active CSV log file if one is open.
 */
void logger_close(void);

#endif
