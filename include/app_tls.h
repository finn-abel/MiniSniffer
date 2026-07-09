#ifndef APP_TLS_H
#define APP_TLS_H

#include <stddef.h>
#include <stdint.h>

#include "app_decoder.h"
#include "common.h"

/*
 * Decodes metadata from a TLS ClientHello record.
 * Does not decrypt TLS or inspect encrypted application data.
 * Returns NEED_MORE for incomplete records or handshakes.
 */
AppDecodeResult app_tls_decode_client_hello(const uint8_t *data, size_t length, AppInfo *out);

#endif
