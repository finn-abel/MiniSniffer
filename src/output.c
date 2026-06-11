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

    print_app_with_prefix(&flow->app, "      flow app: ");
}
