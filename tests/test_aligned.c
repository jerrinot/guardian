/*
 * Test: Aligned allocation functions (should pass)
 * Verifies that memalign/posix_memalign/aligned_alloc work correctly.
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

int main(void) {
    /* Test memalign */
    void *p1 = memalign(64, 1000);
    if (!p1) {
        fprintf(stderr, "memalign(64, 1000) failed\n");
        return 1;
    }
    if ((uintptr_t)p1 % 64 != 0) {
        fprintf(stderr, "memalign didn't return aligned pointer\n");
        return 1;
    }
    memset(p1, 'A', 1000);
    free(p1);

    /* Test posix_memalign */
    void *p2 = NULL;
    int ret = posix_memalign(&p2, 128, 2000);
    if (ret != 0 || !p2) {
        fprintf(stderr, "posix_memalign failed\n");
        return 1;
    }
    if ((uintptr_t)p2 % 128 != 0) {
        fprintf(stderr, "posix_memalign didn't return aligned pointer\n");
        return 1;
    }
    memset(p2, 'B', 2000);
    free(p2);

    /* Test aligned_alloc */
    void *p3 = aligned_alloc(256, 256 * 4); /* size must be multiple of alignment */
    if (!p3) {
        fprintf(stderr, "aligned_alloc(256, 1024) failed\n");
        return 1;
    }
    if ((uintptr_t)p3 % 256 != 0) {
        fprintf(stderr, "aligned_alloc didn't return aligned pointer\n");
        return 1;
    }
    memset(p3, 'C', 256 * 4);
    free(p3);

    /* Test valloc */
    void *p4 = valloc(5000);
    if (!p4) {
        fprintf(stderr, "valloc(5000) failed\n");
        return 1;
    }
    /* valloc returns page-aligned memory */
    if ((uintptr_t)p4 % 4096 != 0) {
        fprintf(stderr, "valloc didn't return page-aligned pointer\n");
        return 1;
    }
    memset(p4, 'D', 5000);
    free(p4);

    printf("All aligned allocation tests passed!\n");
    return 0;
}
