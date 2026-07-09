#ifndef OUTPUT_H
#define OUTPUT_H

#include <stdbool.h>
#include <stddef.h>

#include "flow.h"

/*
 * Prints decoded packet-local application metadata under the packet summary.
 * UNKNOWN or NULL app info is intentionally silent.
 */
void output_print_packet_app(const AppInfo *app);
void output_print_packet_app_status(AppDecodeStatus status, const AppInfo *app);

/*
 * Prints a flow-level app event.
 * The flow boundary exists now so later stream output does not reshape output.
 */
void output_print_flow_app_event(const FlowInfo *flow);

/*
 * Prints one displayed packet as JSON Lines. Text fields are JSON-escaped so
 * control bytes cannot affect terminals or downstream parsers.
 */
void output_print_packet_json(const PacketInfo *packet, const AppInfo *app, const char *app_source,
                              bool payload_enabled, size_t payload_preview_limit);

#endif
