/*
 * Test: aligned allocation APIs remain usable in MGUARD_PROTECT_BELOW mode.
 */
#define _GNU_SOURCE
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(msg) do { fprintf(stderr, "FAIL: %s\n", msg); return 1; } while (0)

static void fill_and_free(void *ptr, size_t size) {
    memset(ptr, 'A', size);
    free(ptr);
}

int main(void) {
    void *p = memalign(8192, 4096);
    if (!p) FAIL("memalign failed");
    if ((uintptr_t)p % 8192 != 0) FAIL("memalign pointer not 8192-aligned");
    fill_and_free(p, 4096);

    void *q = NULL;
    if (posix_memalign(&q, 8192, 8192) != 0 || !q) {
        FAIL("posix_memalign failed");
    }
    if ((uintptr_t)q % 8192 != 0) FAIL("posix_memalign pointer not 8192-aligned");
    fill_and_free(q, 8192);

    void *r = aligned_alloc(8192, 8192);
    if (!r) FAIL("aligned_alloc failed");
    if ((uintptr_t)r % 8192 != 0) FAIL("aligned_alloc pointer not 8192-aligned");
    fill_and_free(r, 8192);

    void *s = valloc(5000);
    if (!s) FAIL("valloc failed");
    if ((uintptr_t)s % 4096 != 0) FAIL("valloc pointer not page-aligned");
    fill_and_free(s, 5000);

    return 0;
}
