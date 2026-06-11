#ifndef OUTPUT_H
#define OUTPUT_H

#include "common.h"

/*
 * Prints decoded packet-local application metadata under the packet summary.
 * UNKNOWN or NULL app info is intentionally silent.
 */
void output_print_packet_app(const AppInfo *app);

/*
 * Prints a flow-level app event.
 * The flow boundary exists now so later stream output does not reshape output.
 */
void output_print_flow_app_event(const FlowInfo *flow);

#endif
