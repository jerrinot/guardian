/*
 * Test: Edge cases for malloc/free
 * Tests boundary conditions, zero sizes, tiny allocations, etc.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define TEST(name) do { printf("  %-50s ", name); fflush(stdout); } while(0)
#define PASS() do { printf("[PASS]\n"); } while(0)
#define FAIL(msg) do { printf("[FAIL] %s\n", msg); return 1; } while(0)

int main(void) {
    printf("=== Edge Case Tests ===\n");

    /* Test 1: malloc(0) - implementation defined, but should not crash */
    TEST("malloc(0)");
    {
        void *p = malloc(0);
        /* Can return NULL or a unique pointer - either is valid */
        if (p) free(p);
        PASS();
    }

    /* Test 2: malloc(1) - single byte */
    TEST("malloc(1) single byte");
    {
        char *p = malloc(1);
        if (!p) FAIL("allocation failed");
        *p = 'X';
        if (*p != 'X') FAIL("data corruption");
        free(p);
        PASS();
    }

    /* Test 3: Tiny allocations (1-16 bytes) */
    TEST("tiny allocations (1-16 bytes)");
    {
        for (size_t sz = 1; sz <= 16; sz++) {
            char *p = malloc(sz);
            if (!p) FAIL("allocation failed");
            memset(p, 0xAA, sz);
            for (size_t i = 0; i < sz; i++) {
                if ((unsigned char)p[i] != 0xAA) FAIL("data corruption");
            }
            free(p);
        }
        PASS();
    }

    /* Test 4: Power-of-2 sizes */
    TEST("power-of-2 sizes (1 to 64KB)");
    {
        for (size_t sz = 1; sz <= 65536; sz *= 2) {
            char *p = malloc(sz);
            if (!p) FAIL("allocation failed");
            memset(p, 0xBB, sz);
            free(p);
        }
        PASS();
    }

    /* Test 5: Page boundary sizes */
    TEST("page boundary sizes (4095, 4096, 4097)");
    {
        size_t sizes[] = {4095, 4096, 4097, 8191, 8192, 8193};
        for (size_t i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
            char *p = malloc(sizes[i]);
            if (!p) FAIL("allocation failed");
            memset(p, 0xCC, sizes[i]);
            free(p);
        }
        PASS();
    }

    /* Test 6: Off-by-one sizes around alignment */
    TEST("alignment boundary sizes (15, 16, 17, 31, 32, 33)");
    {
        size_t sizes[] = {15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129};
        for (size_t i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
            char *p = malloc(sizes[i]);
            if (!p) FAIL("allocation failed");
            memset(p, 0xDD, sizes[i]);
            free(p);
        }
        PASS();
    }

    /* Test 7: free(NULL) - should be safe */
    TEST("free(NULL)");
    {
        free(NULL);
        free(NULL);
        free(NULL);
        PASS();
    }

    /* Test 8: Allocation alignment check */
    TEST("16-byte alignment verification");
    {
        for (int i = 0; i < 100; i++) {
            void *p = malloc(1 + i);
            if (!p) FAIL("allocation failed");
            if ((uintptr_t)p % 16 != 0) {
                printf("ptr=%p not 16-byte aligned for size %d", p, 1+i);
                FAIL("alignment violation");
            }
            free(p);
        }
        PASS();
    }

    /* Test 9: Rapid alloc/free cycles */
    TEST("rapid alloc/free cycles (10000 iterations)");
    {
        for (int i = 0; i < 10000; i++) {
            void *p = malloc(100);
            if (!p) FAIL("allocation failed");
            free(p);
        }
        PASS();
    }

    /* Test 10: Interleaved allocations */
    TEST("interleaved allocations");
    {
        void *a = malloc(100);
        void *b = malloc(200);
        void *c = malloc(300);
        if (!a || !b || !c) FAIL("allocation failed");
        free(b);  /* Free middle one */
        void *d = malloc(150);
        if (!d) FAIL("allocation failed");
        free(a);
        free(d);
        free(c);
        PASS();
    }

    /* Test 11: Many small allocations at once */
    TEST("many small allocations (1000 x 8 bytes)");
    {
        void *ptrs[1000];
        for (int i = 0; i < 1000; i++) {
            ptrs[i] = malloc(8);
            if (!ptrs[i]) FAIL("allocation failed");
        }
        for (int i = 0; i < 1000; i++) {
            free(ptrs[i]);
        }
        PASS();
    }

    /* Test 12: Exact byte access - write to last byte */
    TEST("exact boundary access (last byte)");
    {
        for (size_t sz = 1; sz <= 256; sz++) {
            char *p = malloc(sz);
            if (!p) FAIL("allocation failed");
            p[sz - 1] = 'Z';  /* Write to last valid byte */
            if (p[sz - 1] != 'Z') FAIL("data corruption");
            free(p);
        }
        PASS();
    }

    /* Test 13: First and last byte in various sizes */
    TEST("first and last byte access");
    {
        /* Use sizes >= 2 since for size=1, first and last byte are the same */
        size_t sizes[] = {2, 7, 8, 15, 16, 17, 100, 1000, 4096};
        for (size_t i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
            size_t sz = sizes[i];
            char *p = malloc(sz);
            if (!p) FAIL("allocation failed");
            p[0] = 'A';
            p[sz - 1] = 'Z';
            if (p[0] != 'A' || p[sz - 1] != 'Z') FAIL("data corruption");
            free(p);
        }
        PASS();
    }

    printf("=== All edge case tests passed! ===\n");
    return 0;
}
