#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "capture.h"
#include "filter.h"
#include "logger.h"
#include "parser.h"
#include "stats.h"

#define CAPTURE_SNAPLEN 65535
#define CAPTURE_PROMISCUOUS 0
#define CAPTURE_TIMEOUT_MS 1000

static volatile sig_atomic_t should_stop = 0;

static void handle_sigint(int signal_number) {
    (void)signal_number;
    should_stop = 1;
}

/*
 * Chooses the default libpcap device when the user does not pass --interface.
 * The wrapper keeps the deprecation suppression contained to this one call.
 */
static const char *lookup_default_device(char *error_buffer) {
    /*
     * Step 8 intentionally uses pcap_lookupdev.
     * Some SDKs mark it deprecated, so silence only that warning locally.
     */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    const char *device = pcap_lookupdev(error_buffer);
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

    return device;
}

static int install_sigint_handler(void) {
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_sigint;
    sigemptyset(&action.sa_mask);

    return sigaction(SIGINT, &action, NULL);
}

static void print_open_live_error(const char *device, const char *error_message) {
    fprintf(stderr,
            "Error: pcap_open_live failed for interface '%s': %s\n",
            device,
            error_message);

    if (strstr(error_message, "Permission") != NULL ||
        strstr(error_message, "permission") != NULL ||
        strstr(error_message, "Operation not permitted") != NULL) {
        fprintf(stderr, "Error: packet capture may require sudo or capture permissions.\n");
    }
}

static int interface_exists(const char *device, char *error_buffer) {
    pcap_if_t *devices = NULL;
    pcap_if_t *current;

    if (pcap_findalldevs(&devices, error_buffer) != 0) {
        return 1;
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

/*
 * Opens a live packet capture and processes packets until the displayed count
 * reaches config->max_packets, or forever when max_packets is zero.
 */
int capture_start(const AppConfig *config, PacketStats *stats) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    const char *device;
    pcap_t *handle;
    uint32_t captured_packets = 0;

    if (config == NULL) {
        return 1;
    }

    should_stop = 0;
    if (install_sigint_handler() != 0) {
        fprintf(stderr, "Error: failed to install Ctrl+C handler.\n");
        return 1;
    }

    /*
     * Empty interface means libpcap should choose the default capture device.
     * Otherwise, use the exact interface name parsed from the CLI.
     */
    if (config->interface_name[0] == '\0') {
        device = lookup_default_device(error_buffer);
        if (device == NULL) {
            fprintf(stderr, "Error: no default capture device found: %s\n", error_buffer);
            return 1;
        }
    } else {
        device = config->interface_name;
        if (!interface_exists(device, error_buffer)) {
            fprintf(stderr, "Error: interface '%s' was not found.\n", device);
            return 1;
        }
    }

    printf("Starting capture on interface: %s\n", device);
    printf("Capture would start now.\n");

    /*
     * Open a live capture handle with conservative local-capture settings:
     * full snap length, non-promiscuous mode, and a one-second timeout.
     */
    handle = pcap_open_live(
        device,
        CAPTURE_SNAPLEN,
        CAPTURE_PROMISCUOUS,
        CAPTURE_TIMEOUT_MS,
        error_buffer
    );
    if (handle == NULL) {
        print_open_live_error(device, error_buffer);
        return 1;
    }

    while (!should_stop &&
           (config->max_packets == 0 ||
            captured_packets < (uint32_t)config->max_packets)) {
        struct pcap_pkthdr *header = NULL;
        const unsigned char *packet = NULL;
        PacketInfo info;
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
            pcap_close(handle);
            return 1;
        }
        if (result == -2) {
            break;
        }

        if (parser_parse_packet(packet, header->caplen, &info) != 0) {
            fprintf(stderr, "Packet parsing failed.\n");
            pcap_close(handle);
            return 1;
        }
        if (!filter_packet_matches(config, &info)) {
            continue;
        }

        /*
         * Only displayed packets are numbered, printed, logged, counted for
         * stats, and considered toward --count.
         */
        captured_packets++;
        info.packet_number = captured_packets;
        packet_info_print(&info);
        logger_write(&info);
        stats_update(stats, &info);
    }

    if (should_stop) {
        printf("\nCapture stopped.\n");
    }

    pcap_close(handle);
    return 0;
}
