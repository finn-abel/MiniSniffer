#ifndef STATS_H
#define STATS_H

#include "common.h"
#include "flow.h"

/*
 * Initializes PacketStats counters before capture begins.
 */
void stats_init(PacketStats *stats);

/*
 * Updates PacketStats for one displayed packet.
 */
void stats_update(PacketStats *stats, const PacketInfo *info);

/*
 * Copies a point-in-time flow table summary (see flow_table_snapshot_stats)
 * into PacketStats. Call once, near the end of a capture run, before the
 * flow table is torn down.
 */
void stats_apply_flow_table(PacketStats *stats, const FlowTable *table);

/*
 * Prints a summary of displayed packet counts and average packet size.
 */
void stats_print(const PacketStats *stats);

#endif
