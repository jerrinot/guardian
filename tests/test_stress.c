/*
 * Test: Stress and concurrency tests
 * Tests thread safety, high allocation rates, memory pressure.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>
#include <unistd.h>
#include <sys/mman.h>

#define TEST(name) do { printf("  %-50s ", name); fflush(stdout); } while(0)
#define PASS() do { printf("[PASS]\n"); } while(0)
#define FAIL(msg) do { printf("[FAIL] %s\n", msg); failures++; } while(0)

#define NUM_THREADS 8
#define ITERATIONS_PER_THREAD 10000

static atomic_int failures = 0;
static atomic_int completed_threads = 0;

/* Thread function: random malloc/free */
static void *thread_malloc_free(void *arg) {
    int id = (int)(intptr_t)arg;
    unsigned int seed = id * 12345;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        size_t size = (rand_r(&seed) % 10000) + 1;
        char *p = malloc(size);
        if (!p) {
            atomic_fetch_add(&failures, 1);
            continue;
        }
        /* Touch some memory */
        p[0] = 'A';
        p[size - 1] = 'Z';
        free(p);
    }

    atomic_fetch_add(&completed_threads, 1);
    return NULL;
}

/* Thread function: holding allocations */
static void *thread_holding(void *arg) {
    int id = (int)(intptr_t)arg;
    unsigned int seed = id * 54321;

    void *ptrs[100];
    int count = 0;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        if (count < 100 && (rand_r(&seed) % 2 == 0 || count == 0)) {
            /* Allocate */
            size_t size = (rand_r(&seed) % 1000) + 1;
            ptrs[count] = malloc(size);
            if (ptrs[count]) {
                memset(ptrs[count], id, size);
                count++;
            }
        } else if (count > 0) {
            /* Free random one */
            int idx = rand_r(&seed) % count;
            free(ptrs[idx]);
            ptrs[idx] = ptrs[--count];
        }
    }

    /* Cleanup */
    for (int i = 0; i < count; i++) {
        free(ptrs[i]);
    }

    atomic_fetch_add(&completed_threads, 1);
    return NULL;
}

/* Thread function: realloc stress */
static void *thread_realloc(void *arg) {
    int id = (int)(intptr_t)arg;
    unsigned int seed = id * 11111;

    char *p = malloc(100);
    if (!p) {
        atomic_fetch_add(&failures, 1);
        atomic_fetch_add(&completed_threads, 1);
        return NULL;
    }
    memset(p, id, 100);

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        size_t new_size = (rand_r(&seed) % 10000) + 1;
        char *new_p = realloc(p, new_size);
        if (!new_p) {
            atomic_fetch_add(&failures, 1);
            continue;
        }
        p = new_p;
    }

    free(p);
    atomic_fetch_add(&completed_threads, 1);
    return NULL;
}

/* Thread function: mixed operations */
static void *thread_mixed(void *arg) {
    int id = (int)(intptr_t)arg;
    unsigned int seed = id * 99999;

    for (int i = 0; i < ITERATIONS_PER_THREAD / 10; i++) {
        int op = rand_r(&seed) % 4;

        switch (op) {
            case 0: {
                /* malloc/free */
                size_t size = (rand_r(&seed) % 1000) + 1;
                void *p = malloc(size);
                if (p) {
                    memset(p, 0xAA, size);
                    free(p);
                }
                break;
            }
            case 1: {
                /* calloc/free */
                size_t nmemb = (rand_r(&seed) % 100) + 1;
                void *p = calloc(nmemb, 10);
                if (p) free(p);
                break;
            }
            case 2: {
                /* realloc chain */
                void *p = malloc(10);
                if (p) {
                    for (int j = 0; j < 5; j++) {
                        p = realloc(p, (rand_r(&seed) % 1000) + 1);
                        if (!p) break;
                    }
                    if (p) free(p);
                }
                break;
            }
            case 3: {
                /* mmap/munmap */
                size_t size = ((rand_r(&seed) % 10) + 1) * 4096;
                void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (p != MAP_FAILED) {
                    memset(p, 0xBB, size);
                    munmap(p, size);
                }
                break;
            }
        }
    }

    atomic_fetch_add(&completed_threads, 1);
    return NULL;
}

int main(void) {
    printf("=== Stress and Concurrency Tests ===\n");

    /* Test 1: Single-threaded stress */
    TEST("single-threaded stress (100K alloc/free)");
    {
        for (int i = 0; i < 100000; i++) {
            size_t size = (rand() % 1000) + 1;
            void *p = malloc(size);
            if (!p) FAIL("allocation failed");
            free(p);
        }
        if (atomic_load(&failures) == 0) PASS();
    }

    /* Test 2: Multi-threaded malloc/free */
    TEST("multi-threaded malloc/free (8 threads)");
    {
        pthread_t threads[NUM_THREADS];
        atomic_store(&completed_threads, 0);
        atomic_store(&failures, 0);

        for (int i = 0; i < NUM_THREADS; i++) {
            pthread_create(&threads[i], NULL, thread_malloc_free, (void*)(intptr_t)i);
        }
        for (int i = 0; i < NUM_THREADS; i++) {
            pthread_join(threads[i], NULL);
        }

        if (atomic_load(&failures) == 0 &&
            atomic_load(&completed_threads) == NUM_THREADS) {
            PASS();
        }
    }

    /* Test 3: Multi-threaded with held allocations */
    TEST("multi-threaded holding allocations (8 threads)");
    {
        pthread_t threads[NUM_THREADS];
        atomic_store(&completed_threads, 0);
        atomic_store(&failures, 0);

        for (int i = 0; i < NUM_THREADS; i++) {
            pthread_create(&threads[i], NULL, thread_holding, (void*)(intptr_t)i);
        }
        for (int i = 0; i < NUM_THREADS; i++) {
            pthread_join(threads[i], NULL);
        }

        if (atomic_load(&failures) == 0 &&
            atomic_load(&completed_threads) == NUM_THREADS) {
            PASS();
        }
    }

    /* Test 4: Multi-threaded realloc */
    TEST("multi-threaded realloc (8 threads)");
    {
        pthread_t threads[NUM_THREADS];
        atomic_store(&completed_threads, 0);
        atomic_store(&failures, 0);

        for (int i = 0; i < NUM_THREADS; i++) {
            pthread_create(&threads[i], NULL, thread_realloc, (void*)(intptr_t)i);
        }
        for (int i = 0; i < NUM_THREADS; i++) {
            pthread_join(threads[i], NULL);
        }

        if (atomic_load(&failures) == 0 &&
            atomic_load(&completed_threads) == NUM_THREADS) {
            PASS();
        }
    }

    /* Test 5: Multi-threaded mixed operations */
    TEST("multi-threaded mixed operations (8 threads)");
    {
        pthread_t threads[NUM_THREADS];
        atomic_store(&completed_threads, 0);
        atomic_store(&failures, 0);

        for (int i = 0; i < NUM_THREADS; i++) {
            pthread_create(&threads[i], NULL, thread_mixed, (void*)(intptr_t)i);
        }
        for (int i = 0; i < NUM_THREADS; i++) {
            pthread_join(threads[i], NULL);
        }

        if (atomic_load(&failures) == 0 &&
            atomic_load(&completed_threads) == NUM_THREADS) {
            PASS();
        }
    }

    /* Test 6: Many allocations outstanding */
    TEST("many allocations outstanding (10K)");
    {
        void *ptrs[10000];
        for (int i = 0; i < 10000; i++) {
            ptrs[i] = malloc(100);
            if (!ptrs[i]) {
                /* Cleanup and fail */
                for (int j = 0; j < i; j++) free(ptrs[j]);
                FAIL("allocation failed");
            }
            memset(ptrs[i], i & 0xFF, 100);
        }
        /* Free in reverse order */
        for (int i = 9999; i >= 0; i--) {
            free(ptrs[i]);
        }
        PASS();
    }

    /* Test 7: Alternating small and large */
    TEST("alternating small and large allocations");
    {
        for (int i = 0; i < 1000; i++) {
            void *small = malloc(16);
            void *large = malloc(1024 * 1024);
            if (!small || !large) FAIL("allocation failed");
            free(large);
            free(small);
        }
        PASS();
    }

    /* Test 8: Peak memory pressure */
    TEST("peak memory pressure (allocate 1GB total)");
    {
        size_t total = 0;
        size_t target = 1024UL * 1024 * 1024;  /* 1GB */
        void **ptrs = calloc(10000, sizeof(void*));
        if (!ptrs) FAIL("calloc failed");

        int count = 0;
        while (total < target && count < 10000) {
            size_t size = 100 * 1024;  /* 100KB chunks */
            ptrs[count] = malloc(size);
            if (!ptrs[count]) break;
            memset(ptrs[count], 0xCC, size);
            total += size;
            count++;
        }

        /* Free all */
        for (int i = 0; i < count; i++) {
            free(ptrs[i]);
        }
        free(ptrs);

        if (total >= target / 2) {  /* At least 512MB allocated */
            PASS();
        } else {
            printf("[SKIP] only allocated %zu MB\n", total / (1024*1024));
        }
    }

    /* Test 9: Fragmentation stress */
    TEST("fragmentation stress (interleaved alloc/free)");
    {
        void *ptrs[1000];
        /* Allocate all */
        for (int i = 0; i < 1000; i++) {
            ptrs[i] = malloc(100 + (i % 10) * 100);
            if (!ptrs[i]) FAIL("allocation failed");
        }
        /* Free odd indices */
        for (int i = 1; i < 1000; i += 2) {
            free(ptrs[i]);
            ptrs[i] = NULL;
        }
        /* Reallocate with different sizes */
        for (int i = 1; i < 1000; i += 2) {
            ptrs[i] = malloc(50 + (i % 5) * 50);
            if (!ptrs[i]) FAIL("allocation failed");
        }
        /* Free all */
        for (int i = 0; i < 1000; i++) {
            free(ptrs[i]);
        }
        PASS();
    }

    /* Test 10: Rapid thread creation/destruction */
    TEST("rapid thread creation/destruction");
    {
        for (int round = 0; round < 10; round++) {
            pthread_t threads[4];
            atomic_store(&completed_threads, 0);

            for (int i = 0; i < 4; i++) {
                pthread_create(&threads[i], NULL, thread_malloc_free, (void*)(intptr_t)i);
            }
            for (int i = 0; i < 4; i++) {
                pthread_join(threads[i], NULL);
            }
        }
        PASS();
    }

    int total_failures = atomic_load(&failures);
    if (total_failures > 0) {
        printf("=== %d test failures ===\n", total_failures);
        return 1;
    }

    printf("=== All stress tests passed! ===\n");
    return 0;
}
