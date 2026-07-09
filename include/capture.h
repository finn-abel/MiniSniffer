#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdio.h>

#include "common.h"
#include "config.h"

/*
 * Starts packet capture using the provided application configuration.
 * Updates stats for each displayed packet when stats is not NULL.
 * Returns 0 when capture completes normally.
 * Returns non-zero if libpcap setup or packet capture fails.
 */
int capture_start(const AppConfig *config, PacketStats *stats);

/*
 * Prints libpcap capture interfaces with practical selection hints.
 * Returns 0 when devices are enumerated successfully.
 */
int capture_list_interfaces(FILE *stream);

#endif
