/*
 * Test: Realloc edge cases
 * Tests various realloc scenarios including grow, shrink, NULL, zero size.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define TEST(name) do { printf("  %-50s ", name); fflush(stdout); } while(0)
#define PASS() do { printf("[PASS]\n"); } while(0)
#define FAIL(msg) do { printf("[FAIL] %s\n", msg); return 1; } while(0)

int main(void) {
    printf("=== Realloc Edge Case Tests ===\n");

    /* Test 1: realloc(NULL, size) - should behave like malloc */
    TEST("realloc(NULL, 100) acts like malloc");
    {
        char *p = realloc(NULL, 100);
        if (!p) FAIL("allocation failed");
        memset(p, 'A', 100);
        free(p);
        PASS();
    }

    /* Test 2: realloc(ptr, 0) - should behave like free (implementation defined) */
    TEST("realloc(ptr, 0) frees memory");
    {
        char *p = malloc(100);
        if (!p) FAIL("malloc failed");
        memset(p, 'B', 100);
        void *r = realloc(p, 0);
        /* Result is implementation-defined: NULL or unique pointer */
        if (r) free(r);
        PASS();
    }

    /* Test 3: realloc(NULL, 0) - edge case */
    TEST("realloc(NULL, 0)");
    {
        void *p = realloc(NULL, 0);
        /* Result is implementation-defined */
        if (p) free(p);
        PASS();
    }

    /* Test 4: Grow by 1 byte */
    TEST("realloc grow by 1 byte (100 -> 101)");
    {
        char *p = malloc(100);
        if (!p) FAIL("malloc failed");
        memset(p, 'C', 100);

        p = realloc(p, 101);
        if (!p) FAIL("realloc failed");

        /* Verify original data */
        for (int i = 0; i < 100; i++) {
            if (p[i] != 'C') FAIL("data corruption");
        }
        p[100] = 'D';  /* Write to new byte */
        free(p);
        PASS();
    }

    /* Test 5: Shrink by 1 byte */
    TEST("realloc shrink by 1 byte (100 -> 99)");
    {
        char *p = malloc(100);
        if (!p) FAIL("malloc failed");
        memset(p, 'E', 100);

        p = realloc(p, 99);
        if (!p) FAIL("realloc failed");

        /* Verify data in smaller region */
        for (int i = 0; i < 99; i++) {
            if (p[i] != 'E') FAIL("data corruption");
        }
        free(p);
        PASS();
    }

    /* Test 6: Double the size */
    TEST("realloc double size (100 -> 200)");
    {
        char *p = malloc(100);
        if (!p) FAIL("malloc failed");
        memset(p, 'F', 100);

        p = realloc(p, 200);
        if (!p) FAIL("realloc failed");

        /* Verify original data */
        for (int i = 0; i < 100; i++) {
            if (p[i] != 'F') FAIL("data corruption");
        }
        memset(p + 100, 'G', 100);
        free(p);
        PASS();
    }

    /* Test 7: Halve the size */
    TEST("realloc halve size (200 -> 100)");
    {
        char *p = malloc(200);
        if (!p) FAIL("malloc failed");
        memset(p, 'H', 200);

        p = realloc(p, 100);
        if (!p) FAIL("realloc failed");

        /* Verify data in smaller region */
        for (int i = 0; i < 100; i++) {
            if (p[i] != 'H') FAIL("data corruption");
        }
        free(p);
        PASS();
    }

    /* Test 8: Realloc to same size */
    TEST("realloc to same size (100 -> 100)");
    {
        char *p = malloc(100);
        if (!p) FAIL("malloc failed");
        memset(p, 'I', 100);

        p = realloc(p, 100);
        if (!p) FAIL("realloc failed");

        for (int i = 0; i < 100; i++) {
            if (p[i] != 'I') FAIL("data corruption");
        }
        free(p);
        PASS();
    }

    /* Test 9: Chain of reallocs */
    TEST("chain of reallocs (grow then shrink)");
    {
        char *p = malloc(10);
        if (!p) FAIL("malloc failed");
        memset(p, 'J', 10);

        for (int sz = 20; sz <= 1000; sz += 10) {
            p = realloc(p, sz);
            if (!p) FAIL("realloc grow failed");
        }

        for (int sz = 990; sz >= 10; sz -= 10) {
            p = realloc(p, sz);
            if (!p) FAIL("realloc shrink failed");
        }

        /* Original data should still be in first 10 bytes */
        for (int i = 0; i < 10; i++) {
            if (p[i] != 'J') FAIL("data corruption");
        }
        free(p);
        PASS();
    }

    /* Test 10: Realloc across page boundary */
    TEST("realloc across page boundary (100 -> 5000)");
    {
        char *p = malloc(100);
        if (!p) FAIL("malloc failed");
        memset(p, 'K', 100);

        p = realloc(p, 5000);
        if (!p) FAIL("realloc failed");

        for (int i = 0; i < 100; i++) {
            if (p[i] != 'K') FAIL("data corruption");
        }
        free(p);
        PASS();
    }

    /* Test 11: Realloc tiny to large */
    TEST("realloc tiny to large (1 -> 10000)");
    {
        char *p = malloc(1);
        if (!p) FAIL("malloc failed");
        *p = 'L';

        p = realloc(p, 10000);
        if (!p) FAIL("realloc failed");

        if (*p != 'L') FAIL("data corruption");
        free(p);
        PASS();
    }

    /* Test 12: Realloc large to tiny */
    TEST("realloc large to tiny (10000 -> 1)");
    {
        char *p = malloc(10000);
        if (!p) FAIL("malloc failed");
        p[0] = 'M';

        p = realloc(p, 1);
        if (!p) FAIL("realloc failed");

        if (*p != 'M') FAIL("data corruption");
        free(p);
        PASS();
    }

    /* Test 13: Multiple reallocs with data verification */
    TEST("multiple reallocs preserving unique data");
    {
        char *p = malloc(100);
        if (!p) FAIL("malloc failed");
        for (int i = 0; i < 100; i++) {
            p[i] = (char)(i & 0xFF);
        }

        /* Grow */
        p = realloc(p, 200);
        if (!p) FAIL("realloc failed");
        for (int i = 0; i < 100; i++) {
            if (p[i] != (char)(i & 0xFF)) FAIL("data corruption on grow");
        }

        /* Fill new space */
        for (int i = 100; i < 200; i++) {
            p[i] = (char)(i & 0xFF);
        }

        /* Shrink */
        p = realloc(p, 150);
        if (!p) FAIL("realloc failed");
        for (int i = 0; i < 150; i++) {
            if (p[i] != (char)(i & 0xFF)) FAIL("data corruption on shrink");
        }

        free(p);
        PASS();
    }

    /* Test 14: Realloc alignment preservation */
    TEST("realloc preserves 16-byte alignment");
    {
        for (int initial = 1; initial <= 256; initial++) {
            char *p = malloc(initial);
            if (!p) FAIL("malloc failed");

            p = realloc(p, initial * 2);
            if (!p) FAIL("realloc failed");

            if ((uintptr_t)p % 16 != 0) FAIL("alignment violation");
            free(p);
        }
        PASS();
    }

    /* Test 15: Stress realloc */
    TEST("stress realloc (1000 iterations)");
    {
        char *p = malloc(1);
        if (!p) FAIL("malloc failed");
        *p = 'X';

        for (int i = 0; i < 1000; i++) {
            size_t new_size = (rand() % 10000) + 1;
            char *new_p = realloc(p, new_size);
            if (!new_p) FAIL("realloc failed");
            p = new_p;
            /* First byte should always be preserved or rewritten */
        }
        free(p);
        PASS();
    }

    printf("=== All realloc tests passed! ===\n");
    return 0;
}
