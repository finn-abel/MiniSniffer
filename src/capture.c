#include <pcap/pcap.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "app_decoder.h"
#include "capture.h"
#include "csv_logger.h"
#include "filters.h"
#include "flow.h"
#include "output.h"
#include "parser.h"
#include "stream_buffer.h"
#include "stats.h"
#include "tcp_reassembly.h"

#define CAPTURE_SNAPLEN 65535
#define CAPTURE_PROMISCUOUS 0
#define CAPTURE_TIMEOUT_MS 1000
#define CAPTURE_DEVICE_NAME_LEN 128

static volatile sig_atomic_t should_stop = 0;

static void handle_sigint(int signal_number) {
    (void)signal_number;
    should_stop = 1;
}

static int install_sigint_handler(void) {
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_sigint;
    sigemptyset(&action.sa_mask);

    return sigaction(SIGINT, &action, NULL);
}

static void print_open_live_error(const char *device, const char *error_message) {
    fprintf(stderr, "Error: pcap_open_live failed for interface '%s': %s\n", device, error_message);

    if (strstr(error_message, "Permission") != NULL ||
        strstr(error_message, "permission") != NULL ||
        strstr(error_message, "Operation not permitted") != NULL) {
        fprintf(stderr, "Error: packet capture may require sudo or capture permissions.\n");
    }
}

static pcap_t *open_offline_capture(const char *path, char *error_buffer) {
    pcap_t *handle;

    handle = pcap_open_offline(path, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Error: cannot read pcap file '%s': %s\n", path, error_buffer);
    }

    return handle;
}

static int open_pcap_writer(pcap_t *handle, const char *path, pcap_dumper_t **writer) {
    int fd;
    FILE *file;

    if (handle == NULL || path == NULL || path[0] == '\0' || writer == NULL) {
        return 1;
    }

    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        fprintf(stderr, "Error: cannot create pcap output file '%s': %s\n", path, strerror(errno));
        return 1;
    }

    file = fdopen(fd, "wb");
    if (file == NULL) {
        int saved_errno = errno;

        close(fd);
        unlink(path);
        fprintf(stderr, "Error: cannot initialize pcap output file '%s': %s\n", path,
                strerror(saved_errno));
        return 1;
    }

    *writer = pcap_dump_fopen(handle, file);
    if (*writer == NULL) {
        fprintf(stderr, "Error: cannot initialize pcap output file '%s': %s\n", path,
                pcap_geterr(handle));
        fclose(file);
        unlink(path);
        return 1;
    }

    return 0;
}

static void close_pcap_writer(pcap_dumper_t **writer) {
    if (writer != NULL && *writer != NULL) {
        pcap_dump_close(*writer);
        *writer = NULL;
    }
}

static int has_ipv4_address(const pcap_if_t *device) {
    pcap_addr_t *address;

    if (device == NULL) {
        return 0;
    }

    for (address = device->addresses; address != NULL; address = address->next) {
        if (address->addr != NULL && address->addr->sa_family == AF_INET) {
            return 1;
        }
    }

    return 0;
}

static int has_ipv6_address(const pcap_if_t *device) {
    pcap_addr_t *address;

    if (device == NULL) {
        return 0;
    }

    for (address = device->addresses; address != NULL; address = address->next) {
        if (address->addr != NULL && address->addr->sa_family == AF_INET6) {
            return 1;
        }
    }

    return 0;
}

static int is_loopback_device(const pcap_if_t *device) {
    if (device == NULL) {
        return 0;
    }

    return (device->flags & PCAP_IF_LOOPBACK) != 0;
}

static int is_apple_internal_device_name(const char *name) {
    if (name == NULL) {
        return 0;
    }

    return strncmp(name, "ap", 2) == 0 || strncmp(name, "awdl", 4) == 0 ||
           strncmp(name, "llw", 3) == 0 || strncmp(name, "utun", 4) == 0;
}

static int is_preferred_default_device(const pcap_if_t *device) {
    return device->name != NULL && strncmp(device->name, "en", 2) == 0 &&
           !is_loopback_device(device) && !is_apple_internal_device_name(device->name) &&
           has_ipv4_address(device);
}

static int copy_device_name(char *destination, size_t destination_size, const char *name) {
    size_t length;

    if (destination == NULL || name == NULL || destination_size == 0) {
        return 1;
    }

    length = strlen(name);
    if (length >= destination_size) {
        return 1;
    }

    memcpy(destination, name, length + 1);
    return 0;
}

static void print_interface_hints(FILE *stream, const pcap_if_t *device) {
    int printed = 0;

    fprintf(stream, " [");
    if (is_preferred_default_device(device)) {
        fprintf(stream, "default-candidate");
        printed = 1;
    }
    if (is_loopback_device(device)) {
        fprintf(stream, "%sloopback", printed ? ", " : "");
        printed = 1;
    }
    if (device != NULL && is_apple_internal_device_name(device->name)) {
        fprintf(stream, "%sinternal", printed ? ", " : "");
        printed = 1;
    }
    if (has_ipv4_address(device)) {
        fprintf(stream, "%sipv4", printed ? ", " : "");
        printed = 1;
    }
    if (has_ipv6_address(device)) {
        fprintf(stream, "%sipv6", printed ? ", " : "");
        printed = 1;
    }
    if (!printed) {
        fprintf(stream, "no-addresses");
    }
    fprintf(stream, "]");
}

static void print_interface_line(FILE *stream, const pcap_if_t *device) {
    const char *marker = " ";
    const char *name = "(unnamed)";
    const char *description = "(no description)";

    if (device != NULL) {
        marker = is_preferred_default_device(device) ? "*" : " ";
        if (device->name != NULL) {
            name = device->name;
        }
        if (device->description != NULL && device->description[0] != '\0') {
            description = device->description;
        }
    }

    fprintf(stream, "%s %s - %s", marker, name, description);
    print_interface_hints(stream, device);
    fprintf(stream, "\n");
}

int capture_list_interfaces(FILE *stream) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices = NULL;
    pcap_if_t *current;
    FILE *output = stream == NULL ? stdout : stream;

    if (pcap_findalldevs(&devices, error_buffer) != 0) {
        fprintf(stderr, "Error: failed to list capture interfaces: %s\n", error_buffer);
        return 1;
    }

    fprintf(output, "Capture interfaces:\n");
    for (current = devices; current != NULL; current = current->next) {
        print_interface_line(output, current);
    }
    if (devices == NULL) {
        fprintf(output, "(none)\n");
    }

    pcap_freealldevs(devices);
    return 0;
}

/*
 * Choose a practical default instead of trusting pcap_lookupdev, which often
 * returns macOS internal interfaces such as ap1.
 */
static int choose_default_device(char *device_name, size_t device_name_size, char *error_buffer) {
    pcap_if_t *devices = NULL;
    pcap_if_t *current;
    const char *fallback = NULL;

    if (pcap_findalldevs(&devices, error_buffer) != 0) {
        return 1;
    }

    for (current = devices; current != NULL; current = current->next) {
        if (is_preferred_default_device(current)) {
            if (copy_device_name(device_name, device_name_size, current->name) != 0) {
                pcap_freealldevs(devices);
                return 1;
            }
            pcap_freealldevs(devices);
            return 0;
        }
    }

    for (current = devices; current != NULL; current = current->next) {
        if (current->name != NULL && !is_loopback_device(current) &&
            !is_apple_internal_device_name(current->name) && has_ipv4_address(current)) {
            if (copy_device_name(device_name, device_name_size, current->name) != 0) {
                pcap_freealldevs(devices);
                return 1;
            }
            pcap_freealldevs(devices);
            return 0;
        }
    }

    for (current = devices; current != NULL; current = current->next) {
        if (fallback == NULL && current->name != NULL && !is_loopback_device(current) &&
            !is_apple_internal_device_name(current->name)) {
            fallback = current->name;
        }
    }

    if (fallback == NULL) {
        for (current = devices; current != NULL; current = current->next) {
            if (current->name != NULL && !is_loopback_device(current)) {
                fallback = current->name;
                break;
            }
        }
    }

    if (fallback == NULL || copy_device_name(device_name, device_name_size, fallback) != 0) {
        pcap_freealldevs(devices);
        return 1;
    }

    pcap_freealldevs(devices);
    return 0;
}

static int interface_exists(const char *device, char *error_buffer) {
    pcap_if_t *devices = NULL;
    pcap_if_t *current;

    if (pcap_findalldevs(&devices, error_buffer) != 0) {
        return 0;
    }

    for (current = devices; current != NULL; current = current->next) {
        if (strcmp(current->name, device) == 0) {
            pcap_freealldevs(devices);
            return 1;
        }
    }

    pcap_freealldevs(devices);
    return 0;
}

static void set_packet_timestamp(PacketInfo *info, const struct pcap_pkthdr *header) {
    if (info == NULL || header == NULL) {
        return;
    }

    snprintf(info->timestamp, sizeof(info->timestamp), "%ld.%06ld", (long)header->ts.tv_sec,
             (long)header->ts.tv_usec);
}

static bool flow_decode_stream_app(FlowInfo *flow, FlowDirection direction,
                                   const PacketInfo *packet) {
    TcpReassemblyDirection *tcp_state;
    TcpReassemblyResult reassembly_result;
    const uint8_t *stream_data;
    size_t stream_length;
    AppInfo decoded;

    if (flow == NULL || packet == NULL || packet->protocol != PROTO_TCP ||
        packet->has_tcp_sequence == 0 || packet->has_payload == 0 ||
        packet->payload_capture_length == 0 || flow->app_classified ||
        direction > FLOW_DIR_B_TO_A) {
        return false;
    }

    if (!flow_prepare_reassembly_direction(flow, direction)) {
        return false;
    }
    tcp_state = &flow->directions[direction].tcp;
    reassembly_result =
        tcp_reassembly_process_segment(tcp_state, packet->tcp_sequence, packet->tcp_flags,
                                       packet->payload, packet->payload_capture_length);
    if (reassembly_result == TCP_REASSEMBLY_DROPPED) {
        return false;
    }

    stream_data = stream_buffer_data(&tcp_state->stream);
    stream_length = stream_buffer_length(&tcp_state->stream);
    if (app_decode_stream(packet, stream_data, stream_length, &decoded) == APP_DECODE_OK &&
        decoded.protocol != APP_PROTO_UNKNOWN) {
        flow->app = decoded;
        flow->app_classified = true;
        return true;
    }

    return false;
}

/*
 * Opens a live packet capture and processes packets until the displayed count
 * reaches config->max_packets, or forever when max_packets is zero.
 */
int capture_start(const AppConfig *config, PacketStats *stats) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    char default_device[CAPTURE_DEVICE_NAME_LEN];
    const char *device;
    pcap_t *handle;
    pcap_dumper_t *pcap_writer = NULL;
    int datalink_type;
    FlowTable flow_table = {0};
    bool flow_table_ready = false;
    uint32_t captured_packets = 0;

    if (config == NULL) {
        return 1;
    }

    should_stop = 0;
    if (install_sigint_handler() != 0) {
        fprintf(stderr, "Error: failed to install Ctrl+C handler.\n");
        return 1;
    }

    if (config->read_path_enabled) {
        device = config->read_path;
        handle = open_offline_capture(config->read_path, error_buffer);
        if (handle == NULL) {
            return 1;
        }
    } else {
        /*
         * Empty interface means choose a practical default capture device.
         * Otherwise, use the exact interface name parsed from the CLI.
         */
        if (config->interface_name[0] == '\0') {
            if (choose_default_device(default_device, sizeof(default_device), error_buffer) != 0) {
                fprintf(stderr, "Error: no default capture device found: %s\n", error_buffer);
                return 1;
            }
            device = default_device;
        } else {
            device = config->interface_name;
            if (!interface_exists(device, error_buffer)) {
                fprintf(stderr, "Error: interface '%s' was not found.\n", device);
                return 1;
            }
        }

        if (!config->quiet && !config->json_output) {
            printf("Starting capture on interface: %s\n", device);
        }

        /*
         * Open a live capture handle with conservative local-capture settings:
         * full snap length, non-promiscuous mode, and a one-second timeout.
         */
        handle = pcap_open_live(device, CAPTURE_SNAPLEN, CAPTURE_PROMISCUOUS, CAPTURE_TIMEOUT_MS,
                                error_buffer);
        if (handle == NULL) {
            print_open_live_error(device, error_buffer);
            return 1;
        }
    }

    if (config->read_path_enabled && !config->quiet && !config->json_output) {
        printf("Reading packets from pcap file: %s\n", device);
    }

    datalink_type = pcap_datalink(handle);
    if (!parser_supports_datalink(datalink_type)) {
        fprintf(stderr, "Error: capture source '%s' uses unsupported data-link type %d.\n", device,
                datalink_type);
        pcap_close(handle);
        return 1;
    }

    if (config->write_path_enabled &&
        open_pcap_writer(handle, config->write_path, &pcap_writer) != 0) {
        pcap_close(handle);
        return 1;
    }

    if (config->reassemble) {
        if (!flow_table_init(&flow_table, config->max_flows, config->stream_buffer_bytes,
                             config->flow_timeout_seconds)) {
            fprintf(stderr, "Error: failed to initialize flow table.\n");
            close_pcap_writer(&pcap_writer);
            pcap_close(handle);
            return 1;
        }
        flow_table_ready = true;
    }

    /* Open output only after capture and optional flow state are ready. */
    if (config->logging_enabled != 0 &&
        csv_logger_open(config->log_path, config->decode_app, config->payload_display_enabled != 0,
                        config->payload_preview_bytes, config->log_flush_mode) != 0) {
        close_pcap_writer(&pcap_writer);
        flow_table_cleanup(&flow_table);
        pcap_close(handle);
        return 1;
    }

    while (!should_stop &&
           (config->max_packets == 0 || captured_packets < (uint32_t)config->max_packets)) {
        struct pcap_pkthdr *header = NULL;
        const unsigned char *packet = NULL;
        PacketInfo info;
        AppInfo *packet_app_ptr = NULL;
        FlowInfo *flow = NULL;
        AppInfo *flow_app_ptr = NULL;
        FilterContext filter_context;
        const char *app_source = "none";
        AppInfo *filter_flow_app_ptr = NULL;
        bool flow_was_classified_before_packet = false;
        uint64_t packet_time;
        int result;

        /*
         * pcap_next_ex returns 1 for a packet, 0 for timeout, -1 for error,
         * and -2 when an offline source is exhausted.
         */
        result = pcap_next_ex(handle, &header, &packet);
        if (result == 0) {
            continue;
        }
        if (result == -1) {
            fprintf(stderr, "Error: packet capture failed: %s\n", pcap_geterr(handle));
            (void)csv_logger_close();
            close_pcap_writer(&pcap_writer);
            flow_table_cleanup(&flow_table);
            pcap_close(handle);
            return 1;
        }
        if (result == -2) {
            break;
        }

        if (parser_parse_packet_with_datalink(packet, header->caplen, datalink_type, &info) != 0) {
            fprintf(stderr, "Packet parsing failed.\n");
            (void)csv_logger_close();
            close_pcap_writer(&pcap_writer);
            flow_table_cleanup(&flow_table);
            pcap_close(handle);
            return 1;
        }
        set_packet_timestamp(&info, header);
        packet_time = (uint64_t)header->ts.tv_sec;

        if (flow_table_ready) {
            FlowDirection direction = FLOW_DIR_A_TO_B;

            flow = flow_table_get_or_create(&flow_table, &info, packet_time, &direction);
            if (flow != NULL) {
                flow_update_packet(flow, &info, packet_time, direction);
                flow_was_classified_before_packet = flow->app_classified;
                if (flow->app_classified) {
                    flow_app_ptr = &flow->app;
                    filter_flow_app_ptr = &flow->app;
                    app_source = "flow";
                } else if (config->decode_app && flow_decode_stream_app(flow, direction, &info)) {
                    flow_app_ptr = &flow->app;
                    app_source = "flow";
                }
            }
        }

        if (config->decode_app) {
            AppDecodeResult decode_result = app_decode_packet(&info, &info.app);

            if (decode_result == APP_DECODE_OK && info.app.protocol != APP_PROTO_UNKNOWN) {
                packet_app_ptr = &info.app;
                app_source = "packet";
                if (flow != NULL && !flow->app_classified) {
                    flow->app = info.app;
                    flow->app_classified = true;
                    flow_app_ptr = &flow->app;
                }
            }
        }

        filter_context.packet = &info;
        filter_context.packet_app = packet_app_ptr;
        filter_context.flow_app = filter_flow_app_ptr;
        filter_context.flow_is_classified = flow_was_classified_before_packet;
        if (!filters_match(config, &filter_context)) {
            continue;
        }

        if (!config->json_output && flow != NULL && flow->app_classified &&
            !flow->app_event_printed) {
            output_print_flow_app_event(flow);
            flow->app_event_printed = true;
        }

        /*
         * Only displayed packets are numbered, printed, logged, counted for
         * stats, and considered toward --count.
         */
        captured_packets++;
        info.packet_number = captured_packets;
        if (config->json_output) {
            output_print_packet_json(&info, packet_app_ptr != NULL ? packet_app_ptr : flow_app_ptr,
                                     app_source, config->payload_display_enabled != 0,
                                     config->payload_preview_bytes);
        } else {
            packet_info_print(&info);
            if (config->decode_app && packet_app_ptr != NULL) {
                output_print_packet_app(packet_app_ptr);
            }
            if (config->payload_display_enabled != 0) {
                packet_info_print_payload(&info, config->payload_preview_bytes);
            }
        }
        if (csv_logger_write_packet(&info, packet_app_ptr != NULL ? packet_app_ptr : flow_app_ptr,
                                    app_source) != 0) {
            (void)csv_logger_close();
            close_pcap_writer(&pcap_writer);
            flow_table_cleanup(&flow_table);
            pcap_close(handle);
            return 1;
        }
        if (pcap_writer != NULL) {
            pcap_dump((u_char *)pcap_writer, header, packet);
        }
        stats_update(stats, &info);
    }

    if (should_stop && !config->quiet && !config->json_output) {
        printf("\nCapture stopped.\n");
    }

    flow_table_cleanup(&flow_table);
    close_pcap_writer(&pcap_writer);
    pcap_close(handle);
    return csv_logger_close();
}
