#ifndef CAPTURE_H
#define CAPTURE_H

#include "config.h"

/*
 * Starts packet capture using the provided application configuration.
 * Returns 0 when capture completes normally.
 * Returns non-zero if libpcap setup or packet capture fails.
 */
int capture_start(const AppConfig *config);

#endif
