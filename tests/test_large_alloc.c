/*
 * Test: Large allocations
 * Tests multi-megabyte and gigabyte allocations.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define TEST(name) do { printf("  %-50s ", name); fflush(stdout); } while(0)
#define PASS() do { printf("[PASS]\n"); } while(0)
#define FAIL(msg) do { printf("[FAIL] %s\n", msg); return 1; } while(0)

#define KB (1024UL)
#define MB (1024UL * KB)
#define GB (1024UL * MB)

/* Sparse verification - check boundaries and some internal points */
static int verify_pattern(char *buf, size_t size, char pattern) {
    /* Check first page */
    for (size_t i = 0; i < 4096 && i < size; i++) {
        if (buf[i] != pattern) return 0;
    }
    /* Check last page */
    if (size > 4096) {
        for (size_t i = size - 4096; i < size; i++) {
            if (buf[i] != pattern) return 0;
        }
    }
    /* Check some points in middle */
    for (size_t i = 4096; i < size - 4096; i += MB) {
        if (buf[i] != pattern) return 0;
    }
    return 1;
}

int main(void) {
    printf("=== Large Allocation Tests ===\n");

    /* Test 1: 1 MB allocation */
    TEST("1 MB allocation");
    {
        char *p = malloc(1 * MB);
        if (!p) FAIL("allocation failed");
        memset(p, 0xAA, 1 * MB);
        if (!verify_pattern(p, 1 * MB, 0xAA)) FAIL("data corruption");
        free(p);
        PASS();
    }

    /* Test 2: 10 MB allocation */
    TEST("10 MB allocation");
    {
        char *p = malloc(10 * MB);
        if (!p) FAIL("allocation failed");
        memset(p, 0xBB, 10 * MB);
        if (!verify_pattern(p, 10 * MB, 0xBB)) FAIL("data corruption");
        free(p);
        PASS();
    }

    /* Test 3: 100 MB allocation */
    TEST("100 MB allocation");
    {
        char *p = malloc(100 * MB);
        if (!p) FAIL("allocation failed");
        memset(p, 0xCC, 100 * MB);
        if (!verify_pattern(p, 100 * MB, 0xCC)) FAIL("data corruption");
        free(p);
        PASS();
    }

    /* Test 4: 1 GB allocation */
    TEST("1 GB allocation");
    {
        char *p = malloc(1 * GB);
        if (!p) {
            printf("[SKIP] (not enough memory)\n");
        } else {
            memset(p, 0xDD, 1 * GB);
            if (!verify_pattern(p, 1 * GB, 0xDD)) FAIL("data corruption");
            free(p);
            PASS();
        }
    }

    /* Test 5: Multiple large allocations */
    TEST("multiple 10 MB allocations (10x)");
    {
        void *ptrs[10];
        for (int i = 0; i < 10; i++) {
            ptrs[i] = malloc(10 * MB);
            if (!ptrs[i]) FAIL("allocation failed");
            memset(ptrs[i], 'A' + i, 10 * MB);
        }
        /* Verify all */
        for (int i = 0; i < 10; i++) {
            if (!verify_pattern(ptrs[i], 10 * MB, 'A' + i)) FAIL("data corruption");
        }
        for (int i = 0; i < 10; i++) {
            free(ptrs[i]);
        }
        PASS();
    }

    /* Test 6: Large allocation boundary access */
    TEST("large allocation boundary access");
    {
        size_t size = 50 * MB;
        char *p = malloc(size);
        if (!p) FAIL("allocation failed");

        /* Write to first byte */
        p[0] = 'F';
        /* Write to last byte */
        p[size - 1] = 'L';
        /* Write at 1 MB intervals */
        for (size_t i = 0; i < size; i += MB) {
            p[i] = 'M';
        }

        if (p[0] != 'M') FAIL("first byte corrupted");
        if (p[size - 1] != 'L') FAIL("last byte corrupted");
        free(p);
        PASS();
    }

    /* Test 7: Large aligned allocation */
    TEST("large aligned allocation (64-byte aligned, 10 MB)");
    {
        void *p = NULL;
        if (posix_memalign(&p, 64, 10 * MB) != 0 || !p) FAIL("allocation failed");
        if ((uintptr_t)p % 64 != 0) FAIL("alignment violation");
        memset(p, 0xEE, 10 * MB);
        free(p);
        PASS();
    }

    /* Test 8: Page-aligned large allocation */
    TEST("page-aligned large allocation (4096-byte aligned, 10 MB)");
    {
        void *p = NULL;
        if (posix_memalign(&p, 4096, 10 * MB) != 0 || !p) FAIL("allocation failed");
        if ((uintptr_t)p % 4096 != 0) FAIL("alignment violation");
        memset(p, 0xFF, 10 * MB);
        free(p);
        PASS();
    }

    /* Test 9: Non-power-of-2 large sizes */
    TEST("non-power-of-2 large sizes");
    {
        size_t sizes[] = {
            1 * MB + 12345,
            5 * MB - 1,
            10 * MB + 1,
            7 * MB + 777
        };
        for (size_t i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
            char *p = malloc(sizes[i]);
            if (!p) FAIL("allocation failed");
            p[0] = 'X';
            p[sizes[i] - 1] = 'Y';
            free(p);
        }
        PASS();
    }

    /* Test 10: Large calloc */
    TEST("large calloc (10 MB)");
    {
        char *p = calloc(10 * MB, 1);
        if (!p) FAIL("allocation failed");
        /* Verify zeroed */
        for (size_t i = 0; i < 10 * MB; i += 4096) {
            if (p[i] != 0) FAIL("not zeroed");
        }
        free(p);
        PASS();
    }

    /* Test 11: Large realloc grow */
    TEST("large realloc grow (1 MB -> 10 MB)");
    {
        char *p = malloc(1 * MB);
        if (!p) FAIL("allocation failed");
        memset(p, 0xAA, 1 * MB);

        p = realloc(p, 10 * MB);
        if (!p) FAIL("realloc failed");

        /* Verify original data preserved */
        if (!verify_pattern(p, 1 * MB, 0xAA)) FAIL("data not preserved");
        free(p);
        PASS();
    }

    /* Test 12: Large realloc shrink */
    TEST("large realloc shrink (10 MB -> 1 MB)");
    {
        char *p = malloc(10 * MB);
        if (!p) FAIL("allocation failed");
        memset(p, 0xBB, 10 * MB);

        p = realloc(p, 1 * MB);
        if (!p) FAIL("realloc failed");

        /* Verify data preserved in smaller region */
        if (!verify_pattern(p, 1 * MB, 0xBB)) FAIL("data not preserved");
        free(p);
        PASS();
    }

    printf("=== All large allocation tests passed! ===\n");
    return 0;
}
