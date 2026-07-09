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
    } else if (info->protocol == PROTO_ARP) {
        stats->arp_packets++;
    } else {
        stats->other_packets++;
    }

    if (info->app_decode_status == APP_DECODE_STATUS_NO_MATCH) {
        stats->app_decode_no_match++;
    } else if (info->app_decode_status == APP_DECODE_STATUS_NEED_MORE) {
        stats->app_decode_need_more++;
    } else if (info->app_decode_status == APP_DECODE_STATUS_MALFORMED) {
        stats->app_decode_malformed++;
    } else if (info->app_decode_status == APP_DECODE_STATUS_TRUNCATED) {
        stats->app_decode_truncated++;
    } else if (info->app_decode_status == APP_DECODE_STATUS_DECODED) {
        stats->app_decode_decoded++;
    }
}

void stats_record_raw_packet(PacketStats *stats) {
    if (stats == NULL) {
        return;
    }

    stats->raw_packets_seen++;
}

void stats_record_parse_failure(PacketStats *stats) {
    if (stats == NULL) {
        return;
    }

    stats->parse_failures++;
}

void stats_record_filtered_out(PacketStats *stats) {
    if (stats == NULL) {
        return;
    }

    stats->packets_filtered_out++;
}

/*
 * Folds a point-in-time flow table snapshot into PacketStats so --stats can
 * report flow lifecycle and reassembly memory usage alongside packet counts.
 */
void stats_apply_flow_table(PacketStats *stats, const FlowTable *table) {
    FlowTableStats snapshot;

    if (stats == NULL || table == NULL) {
        return;
    }

    snapshot = flow_table_snapshot_stats(table);
    stats->flow_count_created = snapshot.flows_created;
    stats->flow_count_active_at_exit = snapshot.flows_active;
    stats->flow_closed_fin = snapshot.flows_closed_fin;
    stats->flow_closed_rst = snapshot.flows_closed_rst;
    stats->flow_evicted_idle = snapshot.flows_evicted_idle;
    stats->flow_evicted_capacity = snapshot.flows_evicted_capacity;
    stats->flow_retransmissions = snapshot.retransmissions;
    stats->flow_out_of_order_segments = snapshot.out_of_order_segments;
    stats->flow_overlapping_segments = snapshot.overlapping_segments;
    stats->flow_gaps = snapshot.gaps;
    stats->flow_stream_bytes_in_use = snapshot.stream_bytes_in_use;
    stats->flow_stream_bytes_configured_max = snapshot.stream_bytes_configured_max;
}

void stats_apply_ipv4_fragment_table(PacketStats *stats, const IPv4FragmentTable *table) {
    if (stats == NULL || table == NULL) {
        return;
    }

    stats->ipv4_fragment_bytes_in_use = table->used_bytes;
    stats->ipv4_fragment_bytes_configured_max = table->max_bytes;
}

void stats_apply_pcap_drops(PacketStats *stats, bool available, uint32_t received, uint32_t dropped,
                            uint32_t if_dropped) {
    if (stats == NULL) {
        return;
    }

    stats->pcap_stats_available = available;
    if (!available) {
        stats->pcap_packets_received = 0;
        stats->pcap_packets_dropped = 0;
        stats->pcap_packets_if_dropped = 0;
        return;
    }

    stats->pcap_packets_received = received;
    stats->pcap_packets_dropped = dropped;
    stats->pcap_packets_if_dropped = if_dropped;
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
    printf("Raw packets seen: %u\n", stats->raw_packets_seen);
    printf("Packets filtered out: %u\n", stats->packets_filtered_out);
    printf("Parse failures: %u\n", stats->parse_failures);
    printf("TCP: %u\n", stats->tcp_packets);
    printf("UDP: %u\n", stats->udp_packets);
    printf("ICMP: %u\n", stats->icmp_packets);
    printf("ARP: %u\n", stats->arp_packets);
    printf("Other: %u\n", stats->other_packets);
    printf("Total bytes: %zu\n", stats->total_bytes);
    printf("Average packet size: %zu\n", average_size);
    printf("IPv4 fragments seen: %u\n", stats->ipv4_fragments_seen);
    printf("IPv4 fragments reassembled: %u\n", stats->ipv4_fragments_reassembled);
    printf("IPv4 fragments expired: %u\n", stats->ipv4_fragments_expired);
    printf("IPv4 fragments malformed: %u\n", stats->ipv4_fragments_malformed);
    printf("IPv4 fragments dropped: %u\n", stats->ipv4_fragments_dropped);
    printf("IPv4 fragment bytes in use: %zu\n", stats->ipv4_fragment_bytes_in_use);
    printf("IPv4 fragment bytes configured max: %zu\n", stats->ipv4_fragment_bytes_configured_max);
    if (stats->pcap_stats_available) {
        printf("Pcap packets received: %u\n", stats->pcap_packets_received);
        printf("Pcap packets dropped: %u\n", stats->pcap_packets_dropped);
        printf("Pcap interface drops: %u\n", stats->pcap_packets_if_dropped);
    } else {
        printf("Pcap driver stats: unavailable\n");
    }
    printf("App decode no_match: %u\n", stats->app_decode_no_match);
    printf("App decode need_more: %u\n", stats->app_decode_need_more);
    printf("App decode malformed: %u\n", stats->app_decode_malformed);
    printf("App decode truncated: %u\n", stats->app_decode_truncated);
    printf("App decode decoded: %u\n", stats->app_decode_decoded);
    printf("Flows created: %llu\n", (unsigned long long)stats->flow_count_created);
    printf("Flows active at exit: %llu\n", (unsigned long long)stats->flow_count_active_at_exit);
    printf("Flows closed (FIN): %llu\n", (unsigned long long)stats->flow_closed_fin);
    printf("Flows closed (RST): %llu\n", (unsigned long long)stats->flow_closed_rst);
    printf("Flows evicted (idle): %llu\n", (unsigned long long)stats->flow_evicted_idle);
    printf("Flows evicted (capacity): %llu\n", (unsigned long long)stats->flow_evicted_capacity);
    printf("Flow retransmissions: %llu\n", (unsigned long long)stats->flow_retransmissions);
    printf("Flow out-of-order segments: %llu\n",
           (unsigned long long)stats->flow_out_of_order_segments);
    printf("Flow overlapping segments: %llu\n",
           (unsigned long long)stats->flow_overlapping_segments);
    printf("Flow gaps: %llu\n", (unsigned long long)stats->flow_gaps);
    printf("Flow stream bytes in use: %zu\n", stats->flow_stream_bytes_in_use);
    printf("Flow stream bytes configured max: %zu\n", stats->flow_stream_bytes_configured_max);
}
