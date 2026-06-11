#include "filter.h"
#include "filters.h"

/*
 * Compatibility wrapper for the older packet-only filter API.
 * New app-aware code should call filters_match with a full FilterContext.
 */
int filter_packet_matches(const AppConfig *config, const PacketInfo *info) {
    FilterContext context;

    context.packet = info;
    context.packet_app = NULL;
    context.flow_app = NULL;
    context.flow_is_classified = false;

    return filters_match(config, &context) ? 1 : 0;
}
