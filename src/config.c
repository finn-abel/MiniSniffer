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
    config->filter_payload_text_enabled = 0;
    config->filter_payload_text_length = 0;
    config->filter_payload_hex_enabled = 0;
    config->filter_payload_hex_length = 0;
    config->payload_display_enabled = 0;
    config->payload_preview_bytes = PACKETSCOPE_DEFAULT_PAYLOAD_PREVIEW_BYTES;
    config->logging_enabled = 0;
    config->log_path[0] = '\0';
}
