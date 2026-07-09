#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ipv4_frag.h"

#define IPV4_MAX_TOTAL_LENGTH 65535

static uint16_t read_u16_network(const unsigned char *bytes) {
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static void write_u16_network(unsigned char *bytes, uint16_t value) {
    bytes[0] = (unsigned char)(value >> 8);
    bytes[1] = (unsigned char)value;
}

static bool key_equals(const IPv4FragmentKey *left, const IPv4FragmentKey *right) {
    return left->protocol == right->protocol && left->identification == right->identification &&
           strcmp(left->src_ip, right->src_ip) == 0 && strcmp(left->dst_ip, right->dst_ip) == 0;
}

static void cleanup_datagram(IPv4FragmentDatagram *datagram) {
    if (datagram == NULL) {
        return;
    }

    free(datagram->data);
    memset(datagram, 0, sizeof(*datagram));
}

static void remove_datagram_at(IPv4FragmentTable *table, size_t index) {
    size_t released;

    if (table == NULL || index >= table->count) {
        return;
    }

    released = table->datagrams[index].data_capacity;
    cleanup_datagram(&table->datagrams[index]);
    if (table->used_bytes >= released) {
        table->used_bytes -= released;
    } else {
        table->used_bytes = 0;
    }

    if (index + 1 < table->count) {
        memmove(&table->datagrams[index], &table->datagrams[index + 1],
                (table->count - index - 1) * sizeof(table->datagrams[0]));
    }
    table->count--;
}

bool ipv4_fragment_table_init(IPv4FragmentTable *table, size_t max_datagrams, size_t max_bytes,
                              uint32_t timeout_seconds) {
    if (table == NULL || max_datagrams == 0 ||
        max_datagrams > MINISNIFFER_MAX_IPV4_FRAGMENT_DATAGRAMS || max_bytes == 0 ||
        max_bytes > MINISNIFFER_MAX_IPV4_FRAGMENT_BYTES) {
        return false;
    }

    memset(table, 0, sizeof(*table));
    table->datagrams = calloc(max_datagrams, sizeof(table->datagrams[0]));
    if (table->datagrams == NULL) {
        return false;
    }

    table->max_datagrams = max_datagrams;
    table->max_bytes = max_bytes;
    table->timeout_seconds = timeout_seconds;
    return true;
}

void ipv4_fragment_table_cleanup(IPv4FragmentTable *table) {
    size_t i;

    if (table == NULL) {
        return;
    }

    for (i = 0; i < table->count; i++) {
        cleanup_datagram(&table->datagrams[i]);
    }
    free(table->datagrams);
    memset(table, 0, sizeof(*table));
}

void ipv4_fragment_table_expire(IPv4FragmentTable *table, uint64_t now_seconds,
                                PacketStats *stats) {
    size_t i = 0;

    if (table == NULL || table->datagrams == NULL || table->timeout_seconds == 0) {
        return;
    }

    while (i < table->count) {
        uint64_t idle_seconds = now_seconds >= table->datagrams[i].last_seen_time
                                    ? now_seconds - table->datagrams[i].last_seen_time
                                    : 0;

        if (idle_seconds >= table->timeout_seconds) {
            if (stats != NULL) {
                stats->ipv4_fragments_expired++;
            }
            remove_datagram_at(table, i);
        } else {
            i++;
        }
    }
}

static void make_key(const PacketInfo *fragment, IPv4FragmentKey *key) {
    memset(key, 0, sizeof(*key));
    snprintf(key->src_ip, sizeof(key->src_ip), "%s", fragment->src_ip);
    snprintf(key->dst_ip, sizeof(key->dst_ip), "%s", fragment->dst_ip);
    key->protocol = fragment->ipv4_protocol_number;
    key->identification = fragment->ipv4_identification;
}

static IPv4FragmentDatagram *find_datagram(IPv4FragmentTable *table, const IPv4FragmentKey *key) {
    size_t i;

    for (i = 0; i < table->count; i++) {
        if (key_equals(&table->datagrams[i].key, key)) {
            return &table->datagrams[i];
        }
    }

    return NULL;
}

static bool fragment_is_malformed(const PacketInfo *fragment) {
    size_t end;

    if (fragment == NULL || fragment->is_ipv4_fragment == 0 || fragment->ip_version != 4 ||
        fragment->ipv4_header_length < 20 ||
        fragment->ipv4_header_length > MINISNIFFER_MAX_IPV4_HEADER_BYTES ||
        fragment->ipv4_fragment_payload == NULL) {
        return true;
    }
    if (fragment->ipv4_more_fragments && fragment->ipv4_fragment_payload_length % 8 != 0) {
        return true;
    }
    if (fragment->ipv4_fragment_payload_length == 0) {
        return true;
    }
    if (fragment->ipv4_fragment_offset > IPV4_MAX_TOTAL_LENGTH) {
        return true;
    }
    end = fragment->ipv4_fragment_offset + fragment->ipv4_fragment_payload_length;
    if (end < fragment->ipv4_fragment_offset ||
        end + fragment->ipv4_header_length > IPV4_MAX_TOTAL_LENGTH) {
        return true;
    }

    return false;
}

static bool range_overlaps(const IPv4FragmentDatagram *datagram, size_t start, size_t end) {
    size_t i;

    for (i = 0; i < datagram->range_count; i++) {
        if (start < datagram->ranges[i].end && end > datagram->ranges[i].start) {
            return true;
        }
    }

    return false;
}

static bool add_range(IPv4FragmentDatagram *datagram, size_t start, size_t end) {
    size_t index;

    if (datagram->range_count >= MINISNIFFER_IPV4_FRAGMENT_MAX_RANGES) {
        return false;
    }

    index = datagram->range_count;
    while (index > 0 && datagram->ranges[index - 1].start > start) {
        datagram->ranges[index] = datagram->ranges[index - 1];
        index--;
    }
    datagram->ranges[index].start = start;
    datagram->ranges[index].end = end;
    datagram->range_count++;
    return true;
}

static bool coverage_is_complete(const IPv4FragmentDatagram *datagram) {
    size_t covered = 0;
    size_t i;

    if (!datagram->has_last_fragment || datagram->total_payload_length == 0) {
        return false;
    }

    for (i = 0; i < datagram->range_count; i++) {
        if (datagram->ranges[i].start != covered) {
            return false;
        }
        covered = datagram->ranges[i].end;
        if (covered == datagram->total_payload_length) {
            return true;
        }
        if (covered > datagram->total_payload_length) {
            return false;
        }
    }

    return false;
}

static bool ensure_capacity(IPv4FragmentTable *table, IPv4FragmentDatagram *datagram,
                            size_t capacity) {
    unsigned char *new_data;
    size_t additional;

    if (capacity <= datagram->data_capacity) {
        return true;
    }

    additional = capacity - datagram->data_capacity;
    if (additional > table->max_bytes || table->used_bytes > table->max_bytes - additional) {
        return false;
    }

    new_data = realloc(datagram->data, capacity);
    if (new_data == NULL) {
        return false;
    }
    memset(new_data + datagram->data_capacity, 0, additional);
    datagram->data = new_data;
    datagram->data_capacity = capacity;
    table->used_bytes += additional;
    return true;
}

static IPv4FragmentDatagram *create_datagram(IPv4FragmentTable *table, const PacketInfo *fragment,
                                             const IPv4FragmentKey *key, uint64_t now_seconds) {
    IPv4FragmentDatagram *datagram;

    if (table->count >= table->max_datagrams) {
        return NULL;
    }

    datagram = &table->datagrams[table->count];
    memset(datagram, 0, sizeof(*datagram));
    datagram->active = true;
    datagram->key = *key;
    datagram->last_seen_time = now_seconds;
    datagram->header_length = fragment->ipv4_header_length;
    memcpy(datagram->header, fragment->ipv4_header, fragment->ipv4_header_length);
    table->count++;
    return datagram;
}

static unsigned char *build_packet(const IPv4FragmentDatagram *datagram, size_t *packet_length) {
    unsigned char *packet;
    size_t total_length;
    uint16_t flags_fragment;

    total_length = datagram->header_length + datagram->total_payload_length;
    if (total_length > IPV4_MAX_TOTAL_LENGTH) {
        return NULL;
    }

    packet = malloc(total_length);
    if (packet == NULL) {
        return NULL;
    }

    memcpy(packet, datagram->header, datagram->header_length);
    memcpy(packet + datagram->header_length, datagram->data, datagram->total_payload_length);
    write_u16_network(packet + 2, (uint16_t)total_length);
    flags_fragment = read_u16_network(packet + 6);
    flags_fragment &= 0xe000;
    flags_fragment &= (uint16_t)~0x2000;
    write_u16_network(packet + 6, flags_fragment);
    write_u16_network(packet + 10, 0);
    *packet_length = total_length;
    return packet;
}

static size_t datagram_index(const IPv4FragmentTable *table, const IPv4FragmentDatagram *datagram) {
    return (size_t)(datagram - table->datagrams);
}

IPv4FragmentProcessResult ipv4_fragment_table_process(IPv4FragmentTable *table,
                                                      const PacketInfo *fragment,
                                                      uint64_t now_seconds, PacketStats *stats) {
    IPv4FragmentProcessResult result;
    IPv4FragmentDatagram *datagram;
    IPv4FragmentKey key;
    size_t start;
    size_t end;

    memset(&result, 0, sizeof(result));
    result.result = IPV4_FRAGMENT_IGNORED;
    if (table == NULL || table->datagrams == NULL || fragment == NULL ||
        fragment->is_ipv4_fragment == 0) {
        return result;
    }

    if (stats != NULL) {
        stats->ipv4_fragments_seen++;
    }
    ipv4_fragment_table_expire(table, now_seconds, stats);

    if (fragment_is_malformed(fragment)) {
        if (stats != NULL) {
            stats->ipv4_fragments_malformed++;
        }
        result.result = IPV4_FRAGMENT_MALFORMED;
        return result;
    }

    make_key(fragment, &key);
    datagram = find_datagram(table, &key);
    if (datagram == NULL) {
        datagram = create_datagram(table, fragment, &key, now_seconds);
        if (datagram == NULL) {
            if (stats != NULL) {
                stats->ipv4_fragments_dropped++;
            }
            result.result = IPV4_FRAGMENT_DROPPED;
            return result;
        }
    }

    start = fragment->ipv4_fragment_offset;
    end = start + fragment->ipv4_fragment_payload_length;
    datagram->last_seen_time = now_seconds;

    if (range_overlaps(datagram, start, end) || !add_range(datagram, start, end)) {
        if (stats != NULL) {
            stats->ipv4_fragments_malformed++;
        }
        remove_datagram_at(table, datagram_index(table, datagram));
        result.result = IPV4_FRAGMENT_MALFORMED;
        return result;
    }
    if (!ensure_capacity(table, datagram, end)) {
        if (stats != NULL) {
            stats->ipv4_fragments_dropped++;
        }
        remove_datagram_at(table, datagram_index(table, datagram));
        result.result = IPV4_FRAGMENT_DROPPED;
        return result;
    }

    memcpy(datagram->data + start, fragment->ipv4_fragment_payload,
           fragment->ipv4_fragment_payload_length);
    if (!fragment->ipv4_more_fragments) {
        datagram->has_last_fragment = true;
        datagram->total_payload_length = end;
    }

    if (coverage_is_complete(datagram)) {
        size_t assembled_length = 0;
        unsigned char *assembled = build_packet(datagram, &assembled_length);

        if (assembled == NULL) {
            if (stats != NULL) {
                stats->ipv4_fragments_dropped++;
            }
            remove_datagram_at(table, datagram_index(table, datagram));
            result.result = IPV4_FRAGMENT_DROPPED;
            return result;
        }
        if (stats != NULL) {
            stats->ipv4_fragments_reassembled++;
        }
        result.result = IPV4_FRAGMENT_REASSEMBLED;
        result.packet = assembled;
        result.packet_length = assembled_length;
        remove_datagram_at(table, datagram_index(table, datagram));
        return result;
    }

    result.result = IPV4_FRAGMENT_QUEUED;
    return result;
}
