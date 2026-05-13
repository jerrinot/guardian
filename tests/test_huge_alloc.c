/*
 * Test: huge allocation sizes must fail cleanly instead of wrapping layout
 * arithmetic to a small guarded mapping.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define TEST(name) do { printf("  %-50s ", name); fflush(stdout); } while (0)
#define PASS() do { printf("[PASS]\n"); } while (0)
#define FAIL(msg) do { printf("[FAIL] %s\n", msg); return 1; } while (0)

static int expect_null_errno(void *p, const char *name) {
    if (p != NULL) {
        free(p);
        fprintf(stderr, "%s unexpectedly succeeded\n", name);
        return 0;
    }
    if (errno != ENOMEM) {
        fprintf(stderr, "%s failed with errno=%d, expected ENOMEM\n", name, errno);
        return 0;
    }
    return 1;
}

int main(void) {
    void *(*volatile malloc_fn)(size_t) = malloc;
    void *(*volatile calloc_fn)(size_t, size_t) = calloc;
    void *(*volatile memalign_fn)(size_t, size_t) = memalign;
    int (*volatile posix_memalign_fn)(void **, size_t, size_t) = posix_memalign;
    void *(*volatile aligned_alloc_fn)(size_t, size_t) = aligned_alloc;
    void *(*volatile valloc_fn)(size_t) = valloc;
    void *(*volatile realloc_fn)(void *, size_t) = realloc;
    void *(*volatile mmap_fn)(void *, size_t, int, int, int, off_t) = mmap;

    volatile size_t huge = SIZE_MAX - 8;
    volatile size_t huge_aligned = SIZE_MAX - (SIZE_MAX % 64);

    printf("=== Huge Allocation Tests ===\n");

    TEST("malloc huge size");
    errno = 0;
    if (!expect_null_errno(malloc_fn(huge), "malloc huge")) FAIL("malloc huge succeeded or wrong errno");
    PASS();

    TEST("calloc huge size without multiply overflow");
    errno = 0;
    if (!expect_null_errno(calloc_fn(1, huge), "calloc huge")) FAIL("calloc huge succeeded or wrong errno");
    PASS();

    TEST("memalign huge size");
    errno = 0;
    if (!expect_null_errno(memalign_fn(64, huge), "memalign huge")) FAIL("memalign huge succeeded or wrong errno");
    PASS();

    TEST("posix_memalign huge size");
    void *posix_ptr = (void *)0x1;
    errno = 0;
    int ret = posix_memalign_fn(&posix_ptr, 64, huge);
    if (ret != ENOMEM) FAIL("posix_memalign huge did not return ENOMEM");
    if (posix_ptr != (void *)0x1) FAIL("posix_memalign modified memptr on failure");
    PASS();

    TEST("aligned_alloc huge size");
    errno = 0;
    if (!expect_null_errno(aligned_alloc_fn(64, huge_aligned), "aligned_alloc huge")) {
        FAIL("aligned_alloc huge succeeded or wrong errno");
    }
    PASS();

    TEST("valloc huge size");
    errno = 0;
    if (!expect_null_errno(valloc_fn(huge), "valloc huge")) FAIL("valloc huge succeeded or wrong errno");
    PASS();

    TEST("realloc huge preserves original allocation");
    unsigned char *p = malloc(128);
    if (!p) FAIL("malloc before realloc huge failed");
    memset(p, 0x5a, 128);
    errno = 0;
    void *q = realloc_fn(p, huge);
    if (q != NULL) {
        free(q);
        FAIL("realloc huge unexpectedly succeeded");
    }
    if (errno != ENOMEM) {
        free(p);
        FAIL("realloc huge failed with wrong errno");
    }
    for (size_t i = 0; i < 128; i++) {
        if (p[i] != 0x5a) {
            free(p);
            FAIL("realloc huge corrupted original allocation");
        }
    }
    free(p);
    PASS();

    TEST("mmap huge size");
    errno = 0;
    void *map = mmap_fn(NULL, huge, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map != MAP_FAILED) {
        munmap(map, huge);
        FAIL("mmap huge unexpectedly succeeded");
    }
    if (errno != ENOMEM) FAIL("mmap huge failed with wrong errno");
    PASS();

    printf("=== All huge allocation tests passed! ===\n");
    return 0;
}
