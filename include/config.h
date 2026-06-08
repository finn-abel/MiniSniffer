#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#include "common.h"

/*
 * AppConfig stores runtime options for one PacketScope-C run.
 * Empty interface_name means the capture layer should choose the default device.
 * max_packets of 0 means unlimited capture.
 * Filter values are used only when their matching enabled flag is non-zero.
 * log_path is used only when logging_enabled is non-zero.
 */
typedef struct {
    char interface_name[64];

    int max_packets;
    int stats_mode;

    int filter_protocol_enabled;
    Protocol filter_protocol;

    int filter_port_enabled;
    uint16_t filter_port;

    int filter_host_enabled;
    char filter_host[16];

    int logging_enabled;
    char log_path[256];
} AppConfig;

/*
 * Initializes AppConfig with safe default values.
 * Defaults are applied before any future command-line parsing.
 */
void config_init_defaults(AppConfig *config);

#endif
