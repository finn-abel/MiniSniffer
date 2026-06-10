#ifndef CAPTURE_H
#define CAPTURE_H

#include "common.h"
#include "config.h"

/*
 * Starts packet capture using the provided application configuration.
 * Updates stats for each displayed packet when stats is not NULL.
 * Returns 0 when capture completes normally.
 * Returns non-zero if libpcap setup or packet capture fails.
 */
int capture_start(const AppConfig *config, PacketStats *stats);

#endif
