#ifndef STATS_H
#define STATS_H

#include <stdbool.h>
#include <stdint.h>

#include "common.h"
#include "flow.h"
#include "ipv4_frag.h"

/*
 * Initializes PacketStats counters before capture begins.
 */
void stats_init(PacketStats *stats);

/*
 * Updates PacketStats for one displayed packet.
 */
void stats_update(PacketStats *stats, const PacketInfo *info);

/*
 * Records one packet delivered by libpcap, regardless of parse or filter
 * outcome. Call once per packet retrieved from pcap_next_ex.
 */
void stats_record_raw_packet(PacketStats *stats);

/*
 * Records one packet the parser could not summarize. Parse failures are
 * skipped rather than aborting capture, so this is the only signal that they
 * happened.
 */
void stats_record_parse_failure(PacketStats *stats);

/*
 * Records one packet that parsed successfully but did not pass the active
 * filters, so it was never displayed.
 */
void stats_record_filtered_out(PacketStats *stats);

/*
 * Copies a point-in-time flow table summary (see flow_table_snapshot_stats)
 * into PacketStats. Call once, near the end of a capture run, before the
 * flow table is torn down.
 */
void stats_apply_flow_table(PacketStats *stats, const FlowTable *table);

/*
 * Copies current IPv4 fragment reassembly memory usage into PacketStats.
 * Call once, near the end of a capture run, before the fragment table is
 * torn down.
 */
void stats_apply_ipv4_fragment_table(PacketStats *stats, const IPv4FragmentTable *table);

/*
 * Records libpcap driver-level packet statistics (pcap_stats), when
 * available. Live captures on platforms that support pcap_stats should pass
 * available=true; offline reads and unsupported platforms should pass false,
 * leaving the counters unpopulated.
 */
void stats_apply_pcap_drops(PacketStats *stats, bool available, uint32_t received, uint32_t dropped,
                            uint32_t if_dropped);

/*
 * Prints a summary of displayed packet counts and average packet size.
 */
void stats_print(const PacketStats *stats);

#endif
