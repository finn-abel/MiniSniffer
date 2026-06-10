#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#include "common.h"

#define PACKETSCOPE_MAX_PAYLOAD_PATTERN_BYTES 128
#define PACKETSCOPE_DEFAULT_PAYLOAD_PREVIEW_BYTES 64

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

    int filter_payload_text_enabled;
    unsigned char filter_payload_text[PACKETSCOPE_MAX_PAYLOAD_PATTERN_BYTES];
    size_t filter_payload_text_length;

    int filter_payload_hex_enabled;
    unsigned char filter_payload_hex[PACKETSCOPE_MAX_PAYLOAD_PATTERN_BYTES];
    size_t filter_payload_hex_length;

    int payload_display_enabled;
    size_t payload_preview_bytes;

    int logging_enabled;
    char log_path[256];
} AppConfig;

/*
 * Initializes AppConfig with safe default values.
 * Defaults are applied before any future command-line parsing.
 */
void config_init_defaults(AppConfig *config);

#endif
