/*
 * Test: Calloc edge cases
 * Tests calloc zeroing, overflow detection, various sizes.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>

#define TEST(name) do { printf("  %-50s ", name); fflush(stdout); } while(0)
#define PASS() do { printf("[PASS]\n"); } while(0)
#define FAIL(msg) do { printf("[FAIL] %s\n", msg); return 1; } while(0)

int main(void) {
    printf("=== Calloc Tests ===\n");

    /* Test 1: Basic calloc zeroing */
    TEST("calloc zeroing verification");
    {
        char *p = calloc(1000, 1);
        if (!p) FAIL("allocation failed");
        for (int i = 0; i < 1000; i++) {
            if (p[i] != 0) FAIL("memory not zeroed");
        }
        free(p);
        PASS();
    }

    /* Test 2: calloc with nmemb=0 */
    TEST("calloc(0, 100)");
    {
        void *p = calloc(0, 100);
        /* Implementation-defined: NULL or unique pointer */
        if (p) free(p);
        PASS();
    }

    /* Test 3: calloc with size=0 */
    TEST("calloc(100, 0)");
    {
        void *p = calloc(100, 0);
        /* Implementation-defined: NULL or unique pointer */
        if (p) free(p);
        PASS();
    }

    /* Test 4: calloc(0, 0) */
    TEST("calloc(0, 0)");
    {
        void *p = calloc(0, 0);
        /* Implementation-defined: NULL or unique pointer */
        if (p) free(p);
        PASS();
    }

    /* Test 5: calloc overflow detection - should return NULL */
    TEST("calloc overflow detection (SIZE_MAX, 2)");
    {
        /*
         * Disable warning: we're intentionally testing overflow behavior.
         * Can't use volatile as GCC still detects this at compile time.
         */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Walloc-size-larger-than="
        void *p = calloc(SIZE_MAX, 2);
#pragma GCC diagnostic pop
        if (p != NULL) {
            free(p);
            FAIL("should have returned NULL for overflow");
        }
        PASS();
    }

    /* Test 6: calloc overflow detection - large values */
    TEST("calloc overflow detection (SIZE_MAX/2, 3)");
    {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Walloc-size-larger-than="
        void *p = calloc(SIZE_MAX / 2, 3);
#pragma GCC diagnostic pop
        if (p != NULL) {
            free(p);
            FAIL("should have returned NULL for overflow");
        }
        PASS();
    }

    /* Test 7: calloc single element */
    TEST("calloc(1, 1)");
    {
        char *p = calloc(1, 1);
        if (!p) FAIL("allocation failed");
        if (*p != 0) FAIL("memory not zeroed");
        free(p);
        PASS();
    }

    /* Test 8: calloc array of ints */
    TEST("calloc(1000, sizeof(int))");
    {
        int *arr = calloc(1000, sizeof(int));
        if (!arr) FAIL("allocation failed");
        for (int i = 0; i < 1000; i++) {
            if (arr[i] != 0) FAIL("memory not zeroed");
        }
        /* Use the array */
        for (int i = 0; i < 1000; i++) {
            arr[i] = i * i;
        }
        free(arr);
        PASS();
    }

    /* Test 9: calloc array of structs */
    TEST("calloc array of structs");
    {
        struct {
            int a;
            double b;
            char c[32];
            void *d;
        } *arr = calloc(100, sizeof(*arr));

        if (!arr) FAIL("allocation failed");
        for (int i = 0; i < 100; i++) {
            if (arr[i].a != 0 || arr[i].b != 0.0 || arr[i].d != NULL) {
                FAIL("memory not zeroed");
            }
            for (int j = 0; j < 32; j++) {
                if (arr[i].c[j] != 0) FAIL("memory not zeroed");
            }
        }
        free(arr);
        PASS();
    }

    /* Test 10: calloc page-aligned size */
    TEST("calloc(4096, 1) page-aligned");
    {
        char *p = calloc(4096, 1);
        if (!p) FAIL("allocation failed");
        for (int i = 0; i < 4096; i++) {
            if (p[i] != 0) FAIL("memory not zeroed");
        }
        free(p);
        PASS();
    }

    /* Test 11: calloc multiple pages */
    TEST("calloc(10, 4096) multiple pages");
    {
        char *p = calloc(10, 4096);
        if (!p) FAIL("allocation failed");
        for (int i = 0; i < 10 * 4096; i += 4096) {
            if (p[i] != 0) FAIL("memory not zeroed");
        }
        free(p);
        PASS();
    }

    /* Test 12: calloc alignment */
    TEST("calloc alignment (16-byte)");
    {
        for (int nmemb = 1; nmemb <= 100; nmemb++) {
            void *p = calloc(nmemb, 7);  /* Odd element size */
            if (!p) FAIL("allocation failed");
            if ((uintptr_t)p % 16 != 0) FAIL("alignment violation");
            free(p);
        }
        PASS();
    }

    /* Test 13: calloc vs malloc+memset equivalence */
    TEST("calloc vs malloc+memset equivalence");
    {
        size_t size = 1234;
        char *p1 = calloc(size, 1);
        char *p2 = malloc(size);

        if (!p1 || !p2) FAIL("allocation failed");

        memset(p2, 0, size);

        /* Both should have same content (zeros) */
        if (memcmp(p1, p2, size) != 0) FAIL("content differs");

        free(p1);
        free(p2);
        PASS();
    }

    /* Test 14: calloc many small allocations */
    TEST("calloc many small allocations");
    {
        void *ptrs[1000];
        for (int i = 0; i < 1000; i++) {
            ptrs[i] = calloc(10, sizeof(int));
            if (!ptrs[i]) FAIL("allocation failed");
        }
        for (int i = 0; i < 1000; i++) {
            free(ptrs[i]);
        }
        PASS();
    }

    /* Test 15: calloc large array */
    TEST("calloc large array (1M elements)");
    {
        int *arr = calloc(1000000, sizeof(int));
        if (!arr) FAIL("allocation failed");

        /* Sparse verification */
        for (int i = 0; i < 1000000; i += 1000) {
            if (arr[i] != 0) FAIL("memory not zeroed");
        }
        free(arr);
        PASS();
    }

    /* Test 16: calloc followed by realloc */
    TEST("calloc followed by realloc");
    {
        int *arr = calloc(100, sizeof(int));
        if (!arr) FAIL("calloc failed");

        /* Verify zeroed */
        for (int i = 0; i < 100; i++) {
            if (arr[i] != 0) FAIL("memory not zeroed");
        }

        /* Fill with data */
        for (int i = 0; i < 100; i++) {
            arr[i] = i + 1;
        }

        /* Grow with realloc */
        arr = realloc(arr, 200 * sizeof(int));
        if (!arr) FAIL("realloc failed");

        /* Verify original data preserved */
        for (int i = 0; i < 100; i++) {
            if (arr[i] != i + 1) FAIL("data not preserved");
        }

        free(arr);
        PASS();
    }

    printf("=== All calloc tests passed! ===\n");
    return 0;
}
