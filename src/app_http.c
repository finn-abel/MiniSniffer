#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "app_http.h"

/*
 * Failed HTTP decodes clear AppInfo so callers can leave app protocol UNKNOWN
 * without checking which fields may have been partially filled.
 */
static void clear_app_info(AppInfo *out) {
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
        out->protocol = APP_PROTO_UNKNOWN;
    }
}

static int starts_with(const uint8_t *data, size_t length, const char *prefix) {
    size_t prefix_length = strlen(prefix);

    return length >= prefix_length && memcmp(data, prefix, prefix_length) == 0;
}

/*
 * Requests are detected from known HTTP/1.x methods. Partial method prefixes
 * are treated as "maybe HTTP" so split stream buffers can return NEED_MORE
 * instead of being permanently discarded.
 */
static int maybe_http_request_prefix(const uint8_t *data, size_t length) {
    static const char *const methods[] = {"GET",     "POST",  "PUT",   "DELETE", "HEAD",
                                          "OPTIONS", "PATCH", "TRACE", "CONNECT"};
    size_t i;

    for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        size_t method_length = strlen(methods[i]);

        if (length >= method_length && memcmp(data, methods[i], method_length) == 0) {
            return 1;
        }
        if (length > 0 && length < method_length && memcmp(data, methods[i], length) == 0) {
            return 1;
        }
    }

    return 0;
}

static int looks_like_http(const uint8_t *data, size_t length) {
    return starts_with(data, length, "HTTP/") || maybe_http_request_prefix(data, length);
}

/*
 * HTTP/1.x header parsing is line-oriented and only accepts CRLF framing.
 * Bodies are intentionally ignored after the blank header line.
 */
static const uint8_t *find_crlf(const uint8_t *start, const uint8_t *end) {
    const uint8_t *cursor;

    for (cursor = start; cursor + 1 < end; cursor++) {
        if (cursor[0] == '\r' && cursor[1] == '\n') {
            return cursor;
        }
    }

    return NULL;
}

static const uint8_t *find_header_end(const uint8_t *data, size_t length) {
    size_t i;

    for (i = 0; i + 3 < length; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
            return data + i + 4;
        }
    }

    return NULL;
}

/*
 * Header values are copied into fixed AppInfo fields with whitespace trimming
 * and truncation, keeping metadata bounded even for oversized headers.
 */
static void copy_trimmed(char *destination, size_t destination_size, const uint8_t *start,
                         size_t length) {
    size_t copy_length;

    if (destination == NULL || destination_size == 0) {
        return;
    }

    while (length > 0 && isspace((unsigned char)*start)) {
        start++;
        length--;
    }
    while (length > 0 && isspace((unsigned char)start[length - 1])) {
        length--;
    }

    copy_length = length;
    if (copy_length >= destination_size) {
        copy_length = destination_size - 1;
    }
    memcpy(destination, start, copy_length);
    destination[copy_length] = '\0';
}

static int header_name_equals(const uint8_t *start, size_t length, const char *name) {
    size_t i;
    size_t name_length = strlen(name);

    if (length != name_length) {
        return 0;
    }

    for (i = 0; i < length; i++) {
        if (tolower((unsigned char)start[i]) != tolower((unsigned char)name[i])) {
            return 0;
        }
    }

    return 1;
}

/*
 * A valid request line must be "METHOD SP path SP HTTP/version". Anything that
 * looked like HTTP but fails this shape is treated as malformed.
 */
static int parse_request_line(const uint8_t *line, size_t length, AppInfo *out) {
    const uint8_t *method_end = memchr(line, ' ', length);
    const uint8_t *path_start;
    const uint8_t *path_end;
    const uint8_t *version_start;

    if (method_end == NULL || method_end == line) {
        return 1;
    }
    path_start = method_end + 1;
    path_end = memchr(path_start, ' ', (size_t)(line + length - path_start));
    if (path_end == NULL || path_end == path_start) {
        return 1;
    }
    version_start = path_end + 1;
    if ((size_t)(line + length - version_start) < 8 || memcmp(version_start, "HTTP/", 5) != 0) {
        return 1;
    }

    copy_trimmed(out->http_method, sizeof(out->http_method), line, (size_t)(method_end - line));
    copy_trimmed(out->http_path, sizeof(out->http_path), path_start,
                 (size_t)(path_end - path_start));
    copy_trimmed(out->http_version, sizeof(out->http_version), version_start,
                 (size_t)(line + length - version_start));
    snprintf(out->summary, sizeof(out->summary), "HTTP request %s %s", out->http_method,
             out->http_path);
    return 0;
}

/*
 * Response decoding captures the version, numeric status code, and optional
 * reason phrase. Only the header block is considered.
 */
static int parse_status_line(const uint8_t *line, size_t length, AppInfo *out) {
    const uint8_t *status_start;
    const uint8_t *reason_start;
    int status;

    if (length < 12 || memcmp(line, "HTTP/", 5) != 0) {
        return 1;
    }
    status_start = memchr(line, ' ', length);
    if (status_start == NULL || (size_t)(line + length - status_start) < 4) {
        return 1;
    }
    status_start++;
    if (!isdigit(status_start[0]) || !isdigit(status_start[1]) || !isdigit(status_start[2])) {
        return 1;
    }

    status = (status_start[0] - '0') * 100 + (status_start[1] - '0') * 10 + (status_start[2] - '0');
    copy_trimmed(out->http_version, sizeof(out->http_version), line,
                 (size_t)(status_start - 1 - line));
    out->http_status_code = (uint16_t)status;

    reason_start = status_start + 3;
    if (reason_start < line + length && *reason_start == ' ') {
        reason_start++;
        copy_trimmed(out->http_reason, sizeof(out->http_reason), reason_start,
                     (size_t)(line + length - reason_start));
    }

    snprintf(out->summary, sizeof(out->summary), "HTTP response %u",
             (unsigned int)out->http_status_code);
    return 0;
}

/*
 * Keep header extraction narrow for now: only fields needed by the product
 * goal are copied, while all other headers are skipped.
 */
static void parse_headers(const uint8_t *start, const uint8_t *end, AppInfo *out) {
    const uint8_t *line = start;

    while (line < end) {
        const uint8_t *line_end = find_crlf(line, end);
        const uint8_t *colon;

        if (line_end == NULL || line_end == line) {
            return;
        }

        colon = memchr(line, ':', (size_t)(line_end - line));
        if (colon != NULL) {
            const uint8_t *value = colon + 1;
            size_t name_length = (size_t)(colon - line);
            size_t value_length = (size_t)(line_end - value);

            if (header_name_equals(line, name_length, "Host")) {
                copy_trimmed(out->http_host, sizeof(out->http_host), value, value_length);
            } else if (header_name_equals(line, name_length, "User-Agent")) {
                copy_trimmed(out->http_user_agent, sizeof(out->http_user_agent), value,
                             value_length);
            } else if (header_name_equals(line, name_length, "Content-Type")) {
                copy_trimmed(out->http_content_type, sizeof(out->http_content_type), value,
                             value_length);
            }
        }

        line = line_end + 2;
    }
}

/*
 * Decode only complete HTTP/1.x headers. Missing CRLFCRLF means the caller may
 * provide more bytes later through packet or stream-aware decoding.
 */
AppDecodeResult app_http_decode(const uint8_t *data, size_t length, AppInfo *out) {
    const uint8_t *header_end;
    const uint8_t *line_end;

    clear_app_info(out);
    if (data == NULL || length == 0) {
        return APP_DECODE_NO_MATCH;
    }
    if (!looks_like_http(data, length)) {
        return APP_DECODE_NO_MATCH;
    }

    header_end = find_header_end(data, length);
    if (header_end == NULL) {
        return APP_DECODE_NEED_MORE;
    }

    line_end = find_crlf(data, header_end);
    if (line_end == NULL) {
        return APP_DECODE_MALFORMED;
    }

    out->protocol = APP_PROTO_HTTP;
    if (starts_with(data, (size_t)(line_end - data), "HTTP/")) {
        if (parse_status_line(data, (size_t)(line_end - data), out) != 0) {
            clear_app_info(out);
            return APP_DECODE_MALFORMED;
        }
    } else {
        if (parse_request_line(data, (size_t)(line_end - data), out) != 0) {
            clear_app_info(out);
            return APP_DECODE_MALFORMED;
        }
    }

    parse_headers(line_end + 2, header_end, out);
    return APP_DECODE_OK;
}
