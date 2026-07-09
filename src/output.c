#include <stdio.h>
#include <string.h>

#include "output.h"

/*
 * Keep common DNS names readable while still falling back to numeric types for
 * less common records.
 */
static const char *dns_type_name(uint16_t type) {
    switch (type) {
    case 1:
        return "A";
    case 2:
        return "NS";
    case 5:
        return "CNAME";
    case 28:
        return "AAAA";
    default:
        return NULL;
    }
}

static void print_dns_type(uint16_t type) {
    const char *name = dns_type_name(type);

    if (name != NULL) {
        printf("%s", name);
        return;
    }
    printf("%u", (unsigned int)type);
}

static const char *app_protocol_name(AppProtocol protocol) {
    switch (protocol) {
    case APP_PROTO_HTTP:
        return "http";
    case APP_PROTO_DNS:
        return "dns";
    case APP_PROTO_TLS:
        return "tls";
    case APP_PROTO_UNKNOWN:
    default:
        return "unknown";
    }
}

static const char *protocol_json_name(Protocol protocol) {
    switch (protocol) {
    case PROTO_TCP:
        return "tcp";
    case PROTO_UDP:
        return "udp";
    case PROTO_ICMP:
        return "icmp";
    case PROTO_OTHER:
    default:
        return "other";
    }
}

static const char *transport_name(uint8_t transport_protocol) {
    if (transport_protocol == 6) {
        return "tcp";
    }
    if (transport_protocol == 17) {
        return "udp";
    }

    return "other";
}

static void print_ip_address(IPAddress address) {
    printf("%u.%u.%u.%u", (unsigned int)((address.ipv4 >> 24) & 0xff),
           (unsigned int)((address.ipv4 >> 16) & 0xff), (unsigned int)((address.ipv4 >> 8) & 0xff),
           (unsigned int)(address.ipv4 & 0xff));
}

static void print_escaped_text(const char *text) {
    const unsigned char *cursor = (const unsigned char *)text;

    if (cursor == NULL) {
        return;
    }
    while (*cursor != '\0') {
        if (*cursor >= 0x20 && *cursor <= 0x7e && *cursor != '\\') {
            putchar(*cursor);
        } else if (*cursor == '\\') {
            printf("\\\\");
        } else {
            printf("\\x%02x", (unsigned int)*cursor);
        }
        cursor++;
    }
}

static void print_text_field(const char *name, const char *value) {
    if (value == NULL || value[0] == '\0') {
        return;
    }
    printf(" %s=", name);
    print_escaped_text(value);
}

static void print_json_string(const char *text) {
    const unsigned char *cursor = (const unsigned char *)text;

    putchar('"');
    if (cursor != NULL) {
        while (*cursor != '\0') {
            unsigned char value = *cursor;

            switch (value) {
            case '"':
                printf("\\\"");
                break;
            case '\\':
                printf("\\\\");
                break;
            case '\b':
                printf("\\b");
                break;
            case '\f':
                printf("\\f");
                break;
            case '\n':
                printf("\\n");
                break;
            case '\r':
                printf("\\r");
                break;
            case '\t':
                printf("\\t");
                break;
            default:
                if (value < 0x20 || value == 0x7f) {
                    printf("\\u%04x", (unsigned int)value);
                } else {
                    putchar(value);
                }
                break;
            }
            cursor++;
        }
    }
    putchar('"');
}

static void print_json_text_field(const char *name, const char *value) {
    if (value == NULL || value[0] == '\0') {
        return;
    }

    printf(",\"%s\":", name);
    print_json_string(value);
}

static void print_json_payload_ascii(const PacketInfo *packet, size_t limit) {
    size_t i;

    putchar('"');
    for (i = 0; i < limit; i++) {
        unsigned char value = packet->payload_preview[i];

        if (value == '"' || value == '\\') {
            putchar('\\');
            putchar(value);
        } else if (value >= 0x20 && value <= 0x7e) {
            putchar(value);
        } else {
            putchar('.');
        }
    }
    putchar('"');
}

static void print_json_payload_hex(const PacketInfo *packet, size_t limit) {
    size_t i;

    putchar('"');
    for (i = 0; i < limit; i++) {
        printf("%02x", packet->payload_preview[i]);
        if (i + 1 < limit) {
            putchar(' ');
        }
    }
    putchar('"');
}

static void print_json_app(const AppInfo *app) {
    if (app == NULL || app->protocol == APP_PROTO_UNKNOWN) {
        printf("null");
        return;
    }

    printf("{\"protocol\":");
    print_json_string(app_protocol_name(app->protocol));
    if (app->protocol == APP_PROTO_HTTP) {
        print_json_text_field("method", app->http_method);
        print_json_text_field("host", app->http_host);
        print_json_text_field("path", app->http_path);
        print_json_text_field("version", app->http_version);
        if (app->http_status_code != 0) {
            printf(",\"status\":%u", (unsigned int)app->http_status_code);
        }
    } else if (app->protocol == APP_PROTO_DNS) {
        print_json_text_field("query", app->dns_query_name);
        if (app->dns_query_type != 0) {
            printf(",\"type\":%u", (unsigned int)app->dns_query_type);
        }
        if (app->dns_query_class != 0) {
            printf(",\"class\":%u", (unsigned int)app->dns_query_class);
        }
        printf(",\"rcode\":%u", (unsigned int)app->dns_rcode);
    } else if (app->protocol == APP_PROTO_TLS) {
        print_json_text_field("sni", app->tls_sni);
        print_json_text_field("alpn", app->tls_alpn);
        if (app->tls_record_version != 0) {
            printf(",\"record_version\":\"0x%04x\"", (unsigned int)app->tls_record_version);
        }
        if (app->tls_client_version != 0) {
            printf(",\"client_version\":\"0x%04x\"", (unsigned int)app->tls_client_version);
        }
    }
    printf("}");
}

static const char *normalized_json_app_source(const AppInfo *app, const char *app_source) {
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
 * Shared app formatter keeps packet and future flow output visually consistent.
 * The prefix supplies the output boundary: "app:" or "flow app:".
 */
static void print_app_with_prefix(const AppInfo *app, const char *prefix) {
    if (app == NULL || app->protocol == APP_PROTO_UNKNOWN) {
        return;
    }

    if (app->protocol == APP_PROTO_HTTP) {
        printf("%shttp", prefix);
        print_text_field("method", app->http_method);
        if (app->http_status_code != 0) {
            printf(" status=%u", (unsigned int)app->http_status_code);
        }
        print_text_field("host", app->http_host);
        print_text_field("path", app->http_path);
        printf("\n");
        return;
    }

    if (app->protocol == APP_PROTO_DNS) {
        printf("%sdns", prefix);
        print_text_field("query", app->dns_query_name);
        if (app->dns_query_type != 0) {
            printf(" type=");
            print_dns_type(app->dns_query_type);
        }
        printf("\n");
        return;
    }

    if (app->protocol == APP_PROTO_TLS) {
        printf("%stls", prefix);
        print_text_field("sni", app->tls_sni);
        print_text_field("alpn", app->tls_alpn);
        printf("\n");
    }
}

static void print_flow_app_fields(const AppInfo *app) {
    if (app == NULL || app->protocol == APP_PROTO_UNKNOWN) {
        return;
    }

    printf(" app=%s", app_protocol_name(app->protocol));
    if (app->protocol == APP_PROTO_HTTP) {
        print_text_field("method", app->http_method);
        if (app->http_status_code != 0) {
            printf(" status=%u", (unsigned int)app->http_status_code);
        }
        print_text_field("host", app->http_host);
        print_text_field("path", app->http_path);
        return;
    }
    if (app->protocol == APP_PROTO_DNS) {
        print_text_field("query", app->dns_query_name);
        if (app->dns_query_type != 0) {
            printf(" type=");
            print_dns_type(app->dns_query_type);
        }
        return;
    }
    if (app->protocol == APP_PROTO_TLS) {
        print_text_field("sni", app->tls_sni);
        print_text_field("alpn", app->tls_alpn);
    }
}

/*
 * Packet-local app metadata is printed directly under the packet summary line.
 */
void output_print_packet_app(const AppInfo *app) {
    print_app_with_prefix(app, "      app: ");
}

/*
 * Flow app events use the same field formatting as packet app metadata so the
 * console output does not need to be redesigned when reassembly lands.
 */
void output_print_flow_app_event(const FlowInfo *flow) {
    if (flow == NULL || flow->app.protocol == APP_PROTO_UNKNOWN) {
        return;
    }

    printf("flow %s ", transport_name(flow->key.transport_protocol));
    print_ip_address(flow->key.a_ip);
    printf(":%u <-> ", (unsigned int)flow->key.a_port);
    print_ip_address(flow->key.b_ip);
    printf(":%u", (unsigned int)flow->key.b_port);
    print_flow_app_fields(&flow->app);
    printf("\n");
}

void output_print_packet_json(const PacketInfo *packet, const AppInfo *app, const char *app_source,
                              bool payload_enabled, size_t payload_preview_limit) {
    size_t payload_limit = 0;

    if (packet == NULL) {
        return;
    }

    printf("{\"timestamp\":");
    print_json_string(packet->timestamp);
    printf(",\"packet_number\":%u", packet->packet_number);
    printf(",\"transport\":{\"protocol\":");
    print_json_string(protocol_json_name(packet->protocol));
    if (packet->src_ip[0] != '\0') {
        printf(",\"src_ip\":");
        print_json_string(packet->src_ip);
    }
    if (packet->has_ports != 0) {
        printf(",\"src_port\":%u", (unsigned int)packet->src_port);
    }
    if (packet->dst_ip[0] != '\0') {
        printf(",\"dst_ip\":");
        print_json_string(packet->dst_ip);
    }
    if (packet->has_ports != 0) {
        printf(",\"dst_port\":%u", (unsigned int)packet->dst_port);
    }
    printf("},\"packet_length\":%zu", packet->size);

    if (payload_enabled && packet->has_payload != 0) {
        payload_limit = packet->payload_preview_length;
        if (payload_limit > payload_preview_limit) {
            payload_limit = payload_preview_limit;
        }
        printf(",\"payload\":{\"length\":%zu,\"preview_length\":%zu,\"truncated\":%s,\"hex\":",
               packet->payload_capture_length, payload_limit,
               packet->payload_capture_length > payload_limit ? "true" : "false");
        print_json_payload_hex(packet, payload_limit);
        printf(",\"ascii\":");
        print_json_payload_ascii(packet, payload_limit);
        printf("}");
    }

    printf(",\"app\":");
    print_json_app(app);
    printf(",\"app_source\":");
    print_json_string(normalized_json_app_source(app, app_source));
    printf("}\n");
}
