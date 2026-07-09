#include <string.h>

#include "app_decoder.h"
#include "bench_common.h"

#define BENCH_ITERATIONS 200000

static const uint8_t HTTP_REQUEST[] = "GET /index.html HTTP/1.1\r\n"
                                      "Host: example.com\r\n"
                                      "User-Agent: MiniSnifferBench\r\n"
                                      "\r\n";

static const uint8_t DNS_QUERY[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x03, 'w',  'w',  'w',
                                    0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
                                    0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01};

static const uint8_t TLS_CLIENT_HELLO[] = {
    0x16, 0x03, 0x03, 0x00, 0x43, 0x01, 0x00, 0x00, 0x3f, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x13, 0x01, 0x01, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b,
    'e',  'x',  'a',  'm',  'p',  'l',  'e',  '.',  'c',  'o',  'm'};

static void run_decoder_benchmark(const char *name, AppProtocol preferred, const uint8_t *data,
                                  size_t length) {
    AppInfo info;
    size_t i;
    double start;
    double elapsed;
    volatile int sink = 0;

    start = bench_now_seconds();
    for (i = 0; i < BENCH_ITERATIONS; i++) {
        sink += (int)app_decode_buffer(preferred, data, length, &info);
    }
    elapsed = bench_now_seconds() - start;

    bench_report(name, BENCH_ITERATIONS, elapsed);
    (void)sink;
}

int main(void) {
    run_decoder_benchmark("app_decode_buffer(http)", APP_PROTO_HTTP, HTTP_REQUEST,
                          sizeof(HTTP_REQUEST) - 1);
    run_decoder_benchmark("app_decode_buffer(dns)", APP_PROTO_DNS, DNS_QUERY, sizeof(DNS_QUERY));
    run_decoder_benchmark("app_decode_buffer(tls)", APP_PROTO_TLS, TLS_CLIENT_HELLO,
                          sizeof(TLS_CLIENT_HELLO));
    run_decoder_benchmark("app_decode_buffer(sniffed)", APP_PROTO_UNKNOWN, HTTP_REQUEST,
                          sizeof(HTTP_REQUEST) - 1);
    return 0;
}
