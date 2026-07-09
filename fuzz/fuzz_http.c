#include "app_http.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    AppInfo info;

    app_http_decode(data, size, &info);
    return 0;
}
