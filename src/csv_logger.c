#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "csv_logger.h"

static FILE *log_file = NULL;
static bool app_columns_enabled = false;
static bool payload_columns_enabled = false;
static size_t payload_logging_limit = MINISNIFFER_DEFAULT_PAYLOAD_PREVIEW_BYTES;

/*
 * Empty string keeps UNKNOWN app values as blank CSV fields rather than a
 * display-only label that downstream tools would need to special-case.
 */
static const char *app_protocol_to_string(AppProtocol protocol) {
    switch (protocol) {
        case APP_PROTO_HTTP:
            return "http";
        case APP_PROTO_DNS:
            return "dns";
        case APP_PROTO_TLS:
            return "tls";
        case APP_PROTO_UNKNOWN:
        default:
            return "";
    }
}

static bool csv_text_needs_formula_prefix(const unsigned char *text) {
    if (text == NULL) {
        return false;
    }
    while (*text == ' ') {
        text++;
    }
    return *text == '=' || *text == '+' || *text == '-' || *text == '@';
}

/*
 * Quote all text fields in the app schema. HTTP paths, host names, ALPN lists,
 * and future metadata may contain commas or quotes.
 */
static void write_csv_text(FILE *file, const char *text) {
    const unsigned char *cursor = (const unsigned char *)text;

    fputc('"', file);
    if (cursor != NULL) {
        if (csv_text_needs_formula_prefix(cursor)) {
            fputc('\'', file);
        }
        for (; *cursor != '\0'; cursor++) {
            if (*cursor == '"') {
                fputc('"', file);
            }
            if (*cursor >= 0x20 && *cursor <= 0x7e) {
                fputc(*cursor, file);
            } else {
                fprintf(file, "\\x%02x", (unsigned int)*cursor);
            }
        }
    }
    fputc('"', file);
}

/*
 * Payload columns are legacy opt-in preview columns. They deliberately use the
 * preview buffer, not the larger app decode window.
 */
static void write_payload_hex(FILE *file, const PacketInfo *info) {
    size_t limit;
    size_t i;

    if (info->has_payload == 0) {
        return;
    }

    limit = info->payload_preview_length;
    if (limit > payload_logging_limit) {
        limit = payload_logging_limit;
    }

    for (i = 0; i < limit; i++) {
        fprintf(file, "%02x", info->payload_preview[i]);
        if (i + 1 < limit) {
            fprintf(file, " ");
        }
    }
}

static void write_payload_ascii(FILE *file, const PacketInfo *info) {
    size_t limit;
    size_t i;

    if (info->has_payload == 0) {
        return;
    }

    limit = info->payload_preview_length;
    if (limit > payload_logging_limit) {
        limit = payload_logging_limit;
    }

    if (limit > 0) {
        size_t first = 0;

        while (first < limit && info->payload_preview[first] == ' ') {
            first++;
        }
        if (first < limit &&
            (info->payload_preview[first] == '=' || info->payload_preview[first] == '+' ||
             info->payload_preview[first] == '-' || info->payload_preview[first] == '@')) {
            fputc('\'', file);
        }
    }

    for (i = 0; i < limit; i++) {
        unsigned char value = info->payload_preview[i];

        if (value == '"') {
            fputc('"', file);
        }
        fputc(value >= 32 && value <= 126 ? value : '.', file);
    }
}

/*
 * The app-enabled header is stable for both packet-local and future flow-derived
 * metadata. Legacy headers are preserved when app decoding is disabled.
 */
static int write_header(const char *path) {
    if (app_columns_enabled) {
        if (fprintf(log_file,
                    "timestamp,src_ip,src_port,dst_ip,dst_port,transport_protocol,packet_length,app_protocol,http_method,http_host,http_path,http_status,dns_query,dns_type,dns_class,dns_rcode,tls_sni,tls_alpn,tls_record_version,tls_client_version,app_source\n") < 0) {
            fprintf(stderr, "Error: failed to write CSV header to '%s'.\n", path);
            return 1;
        }
        return 0;
    }

    if (payload_columns_enabled) {
        if (fprintf(log_file,
                    "packet_number,protocol,src_ip,src_port,dst_ip,dst_port,size,payload_length,payload_hex,payload_ascii\n") < 0) {
            fprintf(stderr, "Error: failed to write CSV header to '%s'.\n", path);
            return 1;
        }
        return 0;
    }

    if (fprintf(log_file, "packet_number,protocol,src_ip,src_port,dst_ip,dst_port,size\n") < 0) {
        fprintf(stderr, "Error: failed to write CSV header to '%s'.\n", path);
        return 1;
    }

    return 0;
}

/*
 * The chosen schema is fixed at open time so every row in one file has the same
 * column layout.
 */
int csv_logger_open(
    const char *path,
    bool enable_app_columns,
    bool enable_payload_columns,
    size_t payload_preview_limit
) {
    int fd;

    if (path == NULL || path[0] == '\0') {
        return 1;
    }

    (void)csv_logger_close();
    app_columns_enabled = enable_app_columns;
    payload_columns_enabled = enable_payload_columns;
    payload_logging_limit = payload_preview_limit;
    if (payload_logging_limit > MINISNIFFER_MAX_PAYLOAD_PREVIEW_BYTES) {
        payload_logging_limit = MINISNIFFER_MAX_PAYLOAD_PREVIEW_BYTES;
    }

    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        fprintf(stderr, "Error: cannot open log file '%s': %s\n", path, strerror(errno));
        return 1;
    }
    log_file = fdopen(fd, "w");
    if (log_file == NULL) {
        int saved_errno = errno;

        close(fd);
        unlink(path);
        fprintf(stderr, "Error: cannot initialize log file '%s': %s\n",
                path,
                strerror(saved_errno));
        return 1;
    }

    if (write_header(path) != 0 || fflush(log_file) != 0) {
        (void)csv_logger_close();
        unlink(path);
        return 1;
    }

    return 0;
}

/*
 * Legacy packet rows keep the pre-app schema exactly, including optional payload
 * preview columns, so old CSV consumers are not forced to migrate.
 */
static void write_legacy_packet(const PacketInfo *info) {
    if (payload_columns_enabled) {
        fprintf(log_file,
                "%u,%s,%s,",
                info->packet_number,
                protocol_to_string(info->protocol),
                info->src_ip);

        if (info->has_ports != 0) {
            fprintf(log_file, "%u,%s,%u,",
                    (unsigned int)info->src_port,
                    info->dst_ip,
                    (unsigned int)info->dst_port);
        } else {
            fprintf(log_file, ",%s,,", info->dst_ip);
        }

        fprintf(log_file, "%zu,%zu,\"", info->size, info->payload_capture_length);
        write_payload_hex(log_file, info);
        fprintf(log_file, "\",\"");
        write_payload_ascii(log_file, info);
        fprintf(log_file, "\"\n");
        return;
    }

    if (info->has_ports != 0) {
        fprintf(log_file,
                "%u,%s,%s,%u,%s,%u,%zu\n",
                info->packet_number,
                protocol_to_string(info->protocol),
                info->src_ip,
                (unsigned int)info->src_port,
                info->dst_ip,
                (unsigned int)info->dst_port,
                info->size);
        return;
    }

    fprintf(log_file,
            "%u,%s,%s,,%s,,%zu\n",
            info->packet_number,
            protocol_to_string(info->protocol),
            info->src_ip,
            info->dst_ip,
            info->size);
}

/*
 * Portless packets leave source and destination port fields empty.
 */
static void write_optional_port(const PacketInfo *info, uint16_t port) {
    if (info->has_ports != 0) {
        fprintf(log_file, "%u", (unsigned int)port);
    }
}

/*
 * TLS versions are easier to inspect in their protocol form, e.g. 0x0303.
 */
static void write_hex_version(uint16_t version) {
    if (version != 0) {
        fprintf(log_file, "0x%04x", (unsigned int)version);
    }
}

static const char *normalized_app_source(const AppInfo *app, const char *app_source) {
    if (app == NULL || app->protocol == APP_PROTO_UNKNOWN) {
        return "none";
    }
    if (app_source != NULL &&
        (strcmp(app_source, "packet") == 0 || strcmp(app_source, "flow") == 0)) {
        return app_source;
    }

    return "none";
}

/*
 * App rows always include the full stable app schema. Missing metadata is
 * represented as empty fields, while app_source records packet/flow/none.
 */
static void write_app_packet(const PacketInfo *packet, const AppInfo *app, const char *app_source) {
    AppInfo empty_app;
    const AppInfo *row_app = app;

    memset(&empty_app, 0, sizeof(empty_app));
    if (row_app == NULL) {
        row_app = &empty_app;
    }

    write_csv_text(log_file, packet->timestamp);
    fprintf(log_file, ",");
    write_csv_text(log_file, packet->src_ip);
    fprintf(log_file, ",");
    write_optional_port(packet, packet->src_port);
    fprintf(log_file, ",");
    write_csv_text(log_file, packet->dst_ip);
    fprintf(log_file, ",");
    write_optional_port(packet, packet->dst_port);
    fprintf(log_file, ",%s,%zu,%s,",
            protocol_to_string(packet->protocol),
            packet->size,
            app_protocol_to_string(row_app->protocol));

    write_csv_text(log_file, row_app->http_method);
    fprintf(log_file, ",");
    write_csv_text(log_file, row_app->http_host);
    fprintf(log_file, ",");
    write_csv_text(log_file, row_app->http_path);
    fprintf(log_file, ",");
    if (row_app->http_status_code != 0) {
        fprintf(log_file, "%u", (unsigned int)row_app->http_status_code);
    }
    fprintf(log_file, ",");
    write_csv_text(log_file, row_app->dns_query_name);
    fprintf(log_file, ",");
    if (row_app->dns_query_type != 0) {
        fprintf(log_file, "%u", (unsigned int)row_app->dns_query_type);
    }
    fprintf(log_file, ",");
    if (row_app->dns_query_class != 0) {
        fprintf(log_file, "%u", (unsigned int)row_app->dns_query_class);
    }
    fprintf(log_file, ",");
    fprintf(log_file, "%u,", (unsigned int)row_app->dns_rcode);
    write_csv_text(log_file, row_app->tls_sni);
    fprintf(log_file, ",");
    write_csv_text(log_file, row_app->tls_alpn);
    fprintf(log_file, ",");
    write_hex_version(row_app->tls_record_version);
    fprintf(log_file, ",");
    write_hex_version(row_app->tls_client_version);
    fprintf(log_file, ",");
    write_csv_text(log_file, normalized_app_source(app, app_source));
    fprintf(log_file, "\n");
}

/*
 * Public write path: app schema when enabled, otherwise legacy packet schema.
 */
int csv_logger_write_packet(
    const PacketInfo *packet,
    const AppInfo *app,
    const char *app_source
) {
    if (log_file == NULL || packet == NULL) {
        return 0;
    }

    if (app_columns_enabled) {
        write_app_packet(packet, app, app_source);
    } else {
        write_legacy_packet(packet);
    }

    if (ferror(log_file) || fflush(log_file) != 0) {
        fprintf(stderr, "Error: failed to write CSV log data.\n");
        return 1;
    }
    return 0;
}

/*
 * Close resets only the file handle; the next open call chooses schema state.
 */
int csv_logger_close(void) {
    if (log_file != NULL) {
        if (fclose(log_file) != 0) {
            fprintf(stderr, "Error: failed to close CSV log cleanly.\n");
            log_file = NULL;
            return 1;
        }
        log_file = NULL;
    }
    return 0;
}
