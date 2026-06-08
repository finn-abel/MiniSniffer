#include <string.h>

#include "config.h"

void config_init_defaults(AppConfig *config) {
    if (config == NULL) {
        return;
    }

    /* Zero first so disabled filters and empty strings have predictable values. */
    memset(config, 0, sizeof(*config));

    /* Empty interface means "choose the default device" at capture setup time. */
    config->interface_name[0] = '\0';
    config->max_packets = 0;
    config->stats_mode = 0;
    config->filter_protocol_enabled = 0;
    config->filter_protocol = PROTO_OTHER;
    config->filter_port_enabled = 0;
    config->filter_port = 0;
    config->filter_host_enabled = 0;
    config->filter_host[0] = '\0';
    config->logging_enabled = 0;
    config->log_path[0] = '\0';
}
