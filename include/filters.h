#ifndef FILTERS_H
#define FILTERS_H

#include <stdbool.h>

#include "config.h"

typedef struct {
    const PacketInfo *packet;
    const AppInfo *packet_app;
    const AppInfo *flow_app;
    bool flow_is_classified;
} FilterContext;

/*
 * Checks whether packet and app metadata satisfy all enabled filters.
 * Packet-local app metadata is used now; flow metadata is accepted for later.
 */
bool filters_match(const AppConfig *config, const FilterContext *context);

#endif
