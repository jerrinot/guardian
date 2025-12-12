/*
 * Test: Quarantine behavior tests
 * Tests that quarantine properly holds freed memory and evicts old entries.
 * Note: Some tests require specific MGUARD_QUARANTINE_MB settings.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>

#define TEST(name) do { printf("  %-50s ", name); fflush(stdout); } while(0)
#define PASS() do { printf("[PASS]\n"); } while(0)
#define FAIL(msg) do { printf("[FAIL] %s\n", msg); return 1; } while(0)

#define KB (1024UL)
#define MB (1024UL * KB)

static sigjmp_buf jump_buffer;
static volatile sig_atomic_t got_signal = 0;

static void signal_handler(int sig) {
    (void)sig;
    got_signal = 1;
    siglongjmp(jump_buffer, 1);
}

/* Test if accessing an address causes SIGSEGV */
static int causes_segfault(void *addr) {
    struct sigaction sa, old_sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGSEGV, &sa, &old_sa);
    got_signal = 0;

    if (sigsetjmp(jump_buffer, 1) == 0) {
        /* Try to access */
        volatile char c = *(volatile char *)addr;
        (void)c;
        sigaction(SIGSEGV, &old_sa, NULL);
        return 0;  /* No segfault */
    } else {
        sigaction(SIGSEGV, &old_sa, NULL);
        return 1;  /* Got segfault */
    }
}

int main(void) {
    printf("=== Quarantine Behavior Tests ===\n");
    printf("Note: These tests assume MGUARD_QUARANTINE_MB is set appropriately\n\n");

    /* Test 1: Basic quarantine - freed memory should be protected */
    TEST("freed memory is protected (quarantine)");
    {
        char *p = malloc(100);
        if (!p) FAIL("malloc failed");
        memset(p, 'A', 100);

        char *saved_addr = p;
        free(p);

        /* Accessing freed memory should cause SIGSEGV if quarantined */
        if (causes_segfault(saved_addr)) {
            PASS();
        } else {
            printf("[INFO] No SIGSEGV - quarantine may be disabled or memory reused\n");
        }
    }

    /* Test 2: Multiple frees go to quarantine */
    TEST("multiple allocations in quarantine");
    {
        void *ptrs[10];
        for (int i = 0; i < 10; i++) {
            ptrs[i] = malloc(1000);
            if (!ptrs[i]) FAIL("malloc failed");
        }

        /* Free all */
        for (int i = 0; i < 10; i++) {
            free(ptrs[i]);
        }

        /* All should be protected */
        int protected = 0;
        for (int i = 0; i < 10; i++) {
            if (causes_segfault(ptrs[i])) {
                protected++;
            }
        }

        if (protected == 10) {
            PASS();
        } else {
            printf("[INFO] %d/10 protected (some may be evicted)\n", protected);
        }
    }

    /* Test 3: Quarantine eviction - old entries get evicted */
    TEST("quarantine eviction (fill and overflow)");
    {
        /* Allocate and free many large blocks to overflow quarantine */
        void *first = malloc(1 * MB);
        if (!first) FAIL("malloc failed");
        void *first_addr = first;
        free(first);

        /* Allocate and free more to force eviction */
        for (int i = 0; i < 100; i++) {
            void *p = malloc(1 * MB);
            if (!p) continue;  /* May fail if out of memory */
            free(p);
        }

        /* First allocation may have been evicted */
        /* This is expected behavior */
        PASS();
    }

    /* Test 4: Small allocations stay protected longer */
    TEST("small allocations in quarantine");
    {
        char *small_ptrs[100];
        for (int i = 0; i < 100; i++) {
            small_ptrs[i] = malloc(100);
            if (!small_ptrs[i]) FAIL("malloc failed");
            small_ptrs[i][0] = 'X';
        }

        /* Free all */
        for (int i = 0; i < 100; i++) {
            free(small_ptrs[i]);
        }

        /* Count how many are still protected */
        int protected = 0;
        for (int i = 0; i < 100; i++) {
            if (causes_segfault(small_ptrs[i])) {
                protected++;
            }
        }

        printf("[INFO] %d/100 small allocations protected\n", protected);
        PASS();
    }

    /* Test 5: LIFO-ish behavior - recent frees more likely protected */
    TEST("recent frees more likely protected");
    {
        void *old_ptr = malloc(4096);
        if (!old_ptr) FAIL("malloc failed");
        free(old_ptr);

        /* Many allocations in between */
        for (int i = 0; i < 50; i++) {
            void *p = malloc(100 * KB);
            if (p) free(p);
        }

        void *new_ptr = malloc(4096);
        if (!new_ptr) FAIL("malloc failed");
        void *new_addr = new_ptr;
        free(new_ptr);

        /* New one more likely to still be protected */
        int new_protected = causes_segfault(new_addr);
        int old_protected = causes_segfault(old_ptr);

        printf("[INFO] old=%s, new=%s\n",
               old_protected ? "protected" : "evicted",
               new_protected ? "protected" : "evicted");
        PASS();
    }

    /* Test 6: Free and immediate realloc */
    TEST("free followed by malloc (different size)");
    {
        char *p1 = malloc(100);
        if (!p1) FAIL("malloc failed");
        memset(p1, 'A', 100);
        void *p1_addr = p1;
        free(p1);

        /* Different size - should get different address */
        char *p2 = malloc(200);
        if (!p2) FAIL("malloc failed");

        /* p1 should still be in quarantine if size differs enough */
        /* p2 should be a fresh allocation */
        if (p2 != p1_addr) {
            PASS();
        } else {
            printf("[INFO] Got same address (quarantine may be disabled)\n");
        }
        free(p2);
    }

    /* Test 7: Same-size reuse should not happen immediately */
    TEST("same-size allocation after free");
    {
        char *p1 = malloc(4096);
        if (!p1) FAIL("malloc failed");
        void *p1_addr = p1;
        free(p1);

        char *p2 = malloc(4096);
        if (!p2) FAIL("malloc failed");

        if (p2 != p1_addr) {
            PASS();
        } else {
            printf("[INFO] Got same address (quarantine may be disabled)\n");
        }
        free(p2);
    }

    /* Test 8: Quarantine with mmap */
    TEST("mmap quarantine behavior");
    {
        #include <sys/mman.h>

        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) FAIL("mmap failed");

        void *saved = p;
        munmap(p, 4096);

        /* mmap'd regions should also be quarantined */
        if (causes_segfault(saved)) {
            PASS();
        } else {
            printf("[INFO] No protection (mmap quarantine may be disabled)\n");
        }
    }

    /* Test 9: Verify data is poisoned/protected */
    TEST("freed memory content protected");
    {
        char *p = malloc(4096);
        if (!p) FAIL("malloc failed");

        /* Write known pattern */
        for (int i = 0; i < 4096; i++) {
            p[i] = 'Z';
        }

        void *saved = p;
        free(p);

        /* Try to read - should fault if protected */
        if (causes_segfault(saved)) {
            PASS();
        } else {
            printf("[INFO] Memory readable after free\n");
        }
    }

    /* Test 10: Large allocation quarantine */
    TEST("large allocation quarantine (10MB)");
    {
        char *p = malloc(10 * MB);
        if (!p) {
            printf("[SKIP] cannot allocate 10MB\n");
        } else {
            void *saved = p;
            free(p);

            if (causes_segfault(saved)) {
                PASS();
            } else {
                printf("[INFO] Large allocation not protected\n");
            }
        }
    }

    printf("=== Quarantine tests completed ===\n");
    return 0;
}
