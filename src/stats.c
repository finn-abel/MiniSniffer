#include <stdio.h>
#include <string.h>

#include "stats.h"

/*
 * Clears all counters before a capture run.
 */
void stats_init(PacketStats *stats) {
    if (stats == NULL) {
        return;
    }

    memset(stats, 0, sizeof(*stats));
}

/*
 * Updates counters for one displayed packet.
 * Filtered-out packets should never reach this function.
 */
void stats_update(PacketStats *stats, const PacketInfo *info) {
    if (stats == NULL || info == NULL) {
        return;
    }

    stats->total_packets++;
    stats->total_bytes += info->size;

    if (info->protocol == PROTO_TCP) {
        stats->tcp_packets++;
    } else if (info->protocol == PROTO_UDP) {
        stats->udp_packets++;
    } else if (info->protocol == PROTO_ICMP) {
        stats->icmp_packets++;
    } else {
        stats->other_packets++;
    }
}

/*
 * Prints a compact summary after capture.
 * Average size uses integer division because sizes are displayed as bytes.
 */
void stats_print(const PacketStats *stats) {
    size_t average_size = 0;

    if (stats == NULL) {
        return;
    }

    if (stats->total_packets != 0) {
        average_size = stats->total_bytes / stats->total_packets;
    }

    printf("Displayed packets: %u\n", stats->total_packets);
    printf("TCP: %u\n", stats->tcp_packets);
    printf("UDP: %u\n", stats->udp_packets);
    printf("ICMP: %u\n", stats->icmp_packets);
    printf("Other: %u\n", stats->other_packets);
    printf("Total bytes: %zu\n", stats->total_bytes);
    printf("Average packet size: %zu\n", average_size);
}
