#ifndef FILTER_H
#define FILTER_H

#include "config.h"

/*
 * Checks whether a parsed packet satisfies the active AppConfig filters.
 * Disabled filters are treated as matches.
 * When multiple filters are enabled, every enabled filter must match.
 */
int filter_packet_matches(const AppConfig *config, const PacketInfo *info);

#endif
