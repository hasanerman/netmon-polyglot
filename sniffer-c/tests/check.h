#ifndef CHECK_H
#define CHECK_H

#include <stdio.h>

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_checks++;                                                          \
        if (!(cond)) {                                                       \
            g_failures++;                                                    \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
        }                                                                    \
    } while (0)

#define RUN(test)                                    \
    do {                                             \
        int before_ = g_failures;                    \
        test();                                      \
        printf("%-40s %s\n", #test, g_failures == before_ ? "ok" : "FAILED"); \
    } while (0)

static int check_summary(void)
{
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}

#endif
