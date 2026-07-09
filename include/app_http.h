#ifndef APP_HTTP_H
#define APP_HTTP_H

#include <stddef.h>
#include <stdint.h>

#include "app_decoder.h"
#include "common.h"

/*
 * Decodes HTTP/1.x request or response header metadata from a bounded buffer.
 * Parses only the start line and headers; bodies are intentionally ignored.
 * Returns NEED_MORE when the HTTP header terminator has not arrived yet.
 */
AppDecodeResult app_http_decode(const uint8_t *data, size_t length, AppInfo *out);

#endif
