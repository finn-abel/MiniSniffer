#ifndef IPV4_FRAG_H
#define IPV4_FRAG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"
#include "config.h"

#define MINISNIFFER_IPV4_FRAGMENT_MAX_RANGES 64

typedef struct {
    size_t start;
    size_t end;
} IPv4FragmentRange;

typedef struct {
    char src_ip[MINISNIFFER_IP_TEXT_LEN];
    char dst_ip[MINISNIFFER_IP_TEXT_LEN];
    uint8_t protocol;
    uint16_t identification;
} IPv4FragmentKey;

typedef struct {
    bool active;
    IPv4FragmentKey key;
    uint64_t last_seen_time;
    size_t header_length;
    unsigned char header[MINISNIFFER_MAX_IPV4_HEADER_BYTES];
    unsigned char *data;
    size_t data_capacity;
    bool has_last_fragment;
    size_t total_payload_length;
    size_t range_count;
    IPv4FragmentRange ranges[MINISNIFFER_IPV4_FRAGMENT_MAX_RANGES];
} IPv4FragmentDatagram;

typedef struct {
    IPv4FragmentDatagram *datagrams;
    size_t count;
    size_t max_datagrams;
    size_t max_bytes;
    size_t used_bytes;
    uint32_t timeout_seconds;
} IPv4FragmentTable;

typedef enum {
    IPV4_FRAGMENT_IGNORED = 0,
    IPV4_FRAGMENT_QUEUED,
    IPV4_FRAGMENT_REASSEMBLED,
    IPV4_FRAGMENT_MALFORMED,
    IPV4_FRAGMENT_DROPPED
} IPv4FragmentResult;

typedef struct {
    IPv4FragmentResult result;
    unsigned char *packet;
    size_t packet_length;
} IPv4FragmentProcessResult;

bool ipv4_fragment_table_init(IPv4FragmentTable *table, size_t max_datagrams, size_t max_bytes,
                              uint32_t timeout_seconds);
void ipv4_fragment_table_cleanup(IPv4FragmentTable *table);
void ipv4_fragment_table_expire(IPv4FragmentTable *table, uint64_t now_seconds,
                                PacketStats *stats);
IPv4FragmentProcessResult ipv4_fragment_table_process(IPv4FragmentTable *table,
                                                      const PacketInfo *fragment,
                                                      uint64_t now_seconds, PacketStats *stats);

#endif
