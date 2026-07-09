#ifndef MINISNIFFER_TEST_ASSERT_H
#define MINISNIFFER_TEST_ASSERT_H

#include "test_harness.h"

#ifdef assert
#undef assert
#endif

#define assert(expression) TEST_ASSERT(expression)

#endif
