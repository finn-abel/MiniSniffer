#include "app_tls.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    AppInfo info;

    app_tls_decode_client_hello(data, size, &info);
    return 0;
}
