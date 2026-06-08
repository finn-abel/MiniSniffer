#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#include "common.h"

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

void config_init_defaults(AppConfig *config);

#endif
