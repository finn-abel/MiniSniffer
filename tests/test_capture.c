#include <assert.h>
#include <stdio.h>

#include "capture.h"

static void test_capture_start_rejects_null_config(void) {
    assert(capture_start(NULL, NULL) != 0);
}

int main(void) {
    test_capture_start_rejects_null_config();

    printf("All capture tests passed.\n");

    return 0;
}
