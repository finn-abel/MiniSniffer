#ifndef MINISNIFFER_TEST_HARNESS_H
#define MINISNIFFER_TEST_HARNESS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline void test_fail_expression(const char *file, int line, const char *expression) {
    fprintf(stderr, "%s:%d: test assertion failed: %s\n", file, line, expression);
    exit(1);
}

static inline void test_fail_string_equal(const char *file, int line, const char *left_expression,
                                          const char *right_expression, const char *left,
                                          const char *right) {
    fprintf(stderr, "%s:%d: string comparison failed: %s == %s\n", file, line, left_expression,
            right_expression);
    fprintf(stderr, "  left:  %s\n", left == NULL ? "(null)" : left);
    fprintf(stderr, "  right: %s\n", right == NULL ? "(null)" : right);
    exit(1);
}

static inline void test_fail_contains(const char *file, int line, const char *haystack_expression,
                                      const char *needle_expression, const char *haystack,
                                      const char *needle) {
    fprintf(stderr, "%s:%d: substring comparison failed: %s contains %s\n", file, line,
            haystack_expression, needle_expression);
    fprintf(stderr, "  haystack: %s\n", haystack == NULL ? "(null)" : haystack);
    fprintf(stderr, "  needle:   %s\n", needle == NULL ? "(null)" : needle);
    exit(1);
}

#define TEST_ASSERT(expression)                                                                    \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            test_fail_expression(__FILE__, __LINE__, #expression);                                 \
        }                                                                                          \
    } while (0)

#define TEST_ASSERT_STRING_EQUAL(left, right)                                                      \
    do {                                                                                           \
        const char *test_left_value = (left);                                                      \
        const char *test_right_value = (right);                                                    \
        if (test_left_value == NULL || test_right_value == NULL ||                                 \
            strcmp(test_left_value, test_right_value) != 0) {                                      \
            test_fail_string_equal(__FILE__, __LINE__, #left, #right, test_left_value,             \
                                   test_right_value);                                              \
        }                                                                                          \
    } while (0)

#define TEST_ASSERT_CONTAINS(haystack, needle)                                                     \
    do {                                                                                           \
        const char *test_haystack_value = (haystack);                                              \
        const char *test_needle_value = (needle);                                                  \
        if (test_haystack_value == NULL || test_needle_value == NULL ||                            \
            strstr(test_haystack_value, test_needle_value) == NULL) {                              \
            test_fail_contains(__FILE__, __LINE__, #haystack, #needle, test_haystack_value,        \
                               test_needle_value);                                                 \
        }                                                                                          \
    } while (0)

#endif
