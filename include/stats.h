#ifndef STATS_H
#define STATS_H

#include "common.h"

/*
 * Initializes PacketStats counters before capture begins.
 */
void stats_init(PacketStats *stats);

/*
 * Updates PacketStats for one displayed packet.
 */
void stats_update(PacketStats *stats, const PacketInfo *info);

/*
 * Prints a summary of displayed packet counts and average packet size.
 */
void stats_print(const PacketStats *stats);

#endif
