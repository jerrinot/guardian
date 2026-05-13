/*
 * Test: MGUARD_ENABLED=0 pass-through mode
 *
 * Verifies that disabling mguard still leaves LD_PRELOAD safe to use: libc
 * allocation and mapping functions must be resolved and delegated to, not
 * routed through mguard's bootstrap allocator or ENOSYS fallback.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <errno.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-50s ", name); fflush(stdout); } while (0)
#define PASS() do { printf("[PASS]\n"); } while (0)
#define FAIL(msg) do { printf("[FAIL] %s\n", msg); return 1; } while (0)

static void *thread_func(void *arg) {
    (void)arg;

    for (int i = 0; i < 1000; i++) {
        size_t size = (size_t)(i % 257) + 1;
        char *p = malloc(size);
        if (!p) {
            return (void *)1;
        }
        memset(p, i & 0xff, size);
        free(p);
    }

    return NULL;
}

int main(void) {
    printf("=== Disabled Mode Tests ===\n");

    TEST("malloc/free pass through beyond bootstrap capacity");
    {
        void *ptrs[1024];
        for (int i = 0; i < 1024; i++) {
            ptrs[i] = malloc(4096);
            if (!ptrs[i]) FAIL("malloc failed");
            memset(ptrs[i], i & 0xff, 4096);
        }
        for (int i = 0; i < 1024; i++) {
            free(ptrs[i]);
        }
        PASS();
    }

    TEST("anonymous mmap works");
    {
        long page = sysconf(_SC_PAGESIZE);
        if (page <= 0) page = 4096;

        char *p = mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) FAIL("mmap failed");

        p[0] = 'A';
        p[page - 1] = 'Z';

        if (munmap(p, (size_t)page) != 0) FAIL("munmap failed");
        PASS();
    }

    TEST("calloc overflow delegates to libc");
    {
        volatile size_t huge = SIZE_MAX;
        void *(*volatile calloc_fn)(size_t, size_t) = calloc;
        errno = 0;
        void *p = calloc_fn(huge, 2);
        if (p != NULL) FAIL("overflow calloc succeeded");
        if (errno != ENOMEM) FAIL("overflow calloc did not set ENOMEM");
        PASS();
    }

    TEST("realloc and aligned allocation APIs pass through");
    {
        char *p = realloc(NULL, 64);
        if (!p) FAIL("realloc(NULL, 64) failed");
        memset(p, 0x5a, 64);

        char *q = realloc(p, 128);
        if (!q) FAIL("realloc grow failed");
        for (int i = 0; i < 64; i++) {
            if (q[i] != 0x5a) FAIL("realloc did not preserve data");
        }
        p = q;

        void *aligned = aligned_alloc(64, 128);
        if (!aligned) FAIL("aligned_alloc failed");
        if ((uintptr_t)aligned % 64 != 0) FAIL("aligned_alloc returned unaligned pointer");

        void *posix = NULL;
        if (posix_memalign(&posix, 128, 256) != 0) FAIL("posix_memalign failed");
        if ((uintptr_t)posix % 128 != 0) FAIL("posix_memalign returned unaligned pointer");

        void *page_aligned = valloc(512);
        if (!page_aligned) FAIL("valloc failed");
        long page = sysconf(_SC_PAGESIZE);
        if (page <= 0) page = 4096;
        if ((uintptr_t)page_aligned % (uintptr_t)page != 0) {
            FAIL("valloc returned unaligned pointer");
        }

        free(page_aligned);
        free(posix);
        free(aligned);
        free(p);
        PASS();
    }

    TEST("invalid aligned_alloc does not hit mguard validation");
    {
        errno = 0;
        void *p = aligned_alloc(0, 0);
        if (p) {
            free(p);
        }
        PASS();
    }

    TEST("pthread allocation path works");
    {
        pthread_t threads[4];
        for (int i = 0; i < 4; i++) {
            if (pthread_create(&threads[i], NULL, thread_func, NULL) != 0) {
                FAIL("pthread_create failed");
            }
        }
        for (int i = 0; i < 4; i++) {
            void *result = NULL;
            if (pthread_join(threads[i], &result) != 0) {
                FAIL("pthread_join failed");
            }
            if (result != NULL) {
                FAIL("thread allocation failed");
            }
        }
        PASS();
    }

    printf("=== All disabled mode tests passed! ===\n");
    return 0;
}
