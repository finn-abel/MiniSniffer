#include <stdio.h>

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
    printf("%u.%u.%u.%u",
           (unsigned int)((address.ipv4 >> 24) & 0xff),
           (unsigned int)((address.ipv4 >> 16) & 0xff),
           (unsigned int)((address.ipv4 >> 8) & 0xff),
           (unsigned int)(address.ipv4 & 0xff));
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
        if (app->http_method[0] != '\0') {
            printf(" method=%s", app->http_method);
        }
        if (app->http_status_code != 0) {
            printf(" status=%u", (unsigned int)app->http_status_code);
        }
        if (app->http_host[0] != '\0') {
            printf(" host=%s", app->http_host);
        }
        if (app->http_path[0] != '\0') {
            printf(" path=%s", app->http_path);
        }
        printf("\n");
        return;
    }

    if (app->protocol == APP_PROTO_DNS) {
        printf("%sdns", prefix);
        if (app->dns_query_name[0] != '\0') {
            printf(" query=%s", app->dns_query_name);
        }
        if (app->dns_query_type != 0) {
            printf(" type=");
            print_dns_type(app->dns_query_type);
        }
        printf("\n");
        return;
    }

    if (app->protocol == APP_PROTO_TLS) {
        printf("%stls", prefix);
        if (app->tls_sni[0] != '\0') {
            printf(" sni=%s", app->tls_sni);
        }
        if (app->tls_alpn[0] != '\0') {
            printf(" alpn=%s", app->tls_alpn);
        }
        printf("\n");
    }
}

static void print_flow_app_fields(const AppInfo *app) {
    if (app == NULL || app->protocol == APP_PROTO_UNKNOWN) {
        return;
    }

    printf(" app=%s", app_protocol_name(app->protocol));
    if (app->protocol == APP_PROTO_HTTP) {
        if (app->http_method[0] != '\0') {
            printf(" method=%s", app->http_method);
        }
        if (app->http_status_code != 0) {
            printf(" status=%u", (unsigned int)app->http_status_code);
        }
        if (app->http_host[0] != '\0') {
            printf(" host=%s", app->http_host);
        }
        if (app->http_path[0] != '\0') {
            printf(" path=%s", app->http_path);
        }
        return;
    }
    if (app->protocol == APP_PROTO_DNS) {
        if (app->dns_query_name[0] != '\0') {
            printf(" query=%s", app->dns_query_name);
        }
        if (app->dns_query_type != 0) {
            printf(" type=");
            print_dns_type(app->dns_query_type);
        }
        return;
    }
    if (app->protocol == APP_PROTO_TLS) {
        if (app->tls_sni[0] != '\0') {
            printf(" sni=%s", app->tls_sni);
        }
        if (app->tls_alpn[0] != '\0') {
            printf(" alpn=%s", app->tls_alpn);
        }
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

    printf("flow %s ",
           transport_name(flow->key.transport_protocol));
    print_ip_address(flow->key.a_ip);
    printf(":%u <-> ", (unsigned int)flow->key.a_port);
    print_ip_address(flow->key.b_ip);
    printf(":%u", (unsigned int)flow->key.b_port);
    print_flow_app_fields(&flow->app);
    printf("\n");
}
