/*
 * quarantine.c - Ring buffer holding freed allocations for use-after-free detection
 *
 * Quarantined memory uses MADV_GUARD so it consumes virtual address space only,
 * not physical RAM. This allows large quarantine sizes (default 1M entries).
 */

#include "quarantine.h"
#include "registry.h"
#include "config.h"
#include "guard.h"
#include "interpose.h"
#include <pthread.h>
#include <sys/mman.h>
#include <stdio.h>

#define TRACE(fmt, ...) \
    do { \
        if (g_config.verbose) { \
            fprintf(stderr, "[mguard] " fmt "\n", ##__VA_ARGS__); \
        } \
    } while (0)

#define EVICT_BATCH_SIZE 32  /* Max entries to evict per batch */

typedef struct {
    alloc_entry_t **ring;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t count;
    pthread_mutex_t lock;
} quarantine_t;

static quarantine_t quarantine;

void quarantine_init(void) {
    size_t capacity = g_config.quarantine_entries;
    if (capacity == 0) {
        quarantine.ring = NULL;
        quarantine.capacity = 0;
        return;
    }

    /* Allocate ring buffer via mmap to avoid malloc recursion */
    size_t ring_bytes = capacity * sizeof(alloc_entry_t *);
    quarantine.ring = real_mmap(NULL, ring_bytes, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (quarantine.ring == MAP_FAILED) {
        quarantine.ring = NULL;
        quarantine.capacity = 0;
        return;
    }

    quarantine.capacity = capacity;
    quarantine.head = 0;
    quarantine.tail = 0;
    quarantine.count = 0;
    pthread_mutex_init(&quarantine.lock, NULL);

    if (g_config.verbose) {
        fprintf(stderr, "[mguard] quarantine: %zu entries allocated\n", capacity);
    }
}

/*
 * Collect entries to evict while holding lock.
 * Returns number of entries collected.
 */
static size_t collect_evict_batch(alloc_entry_t **batch, size_t max_count) {
    size_t collected = 0;

    while (collected < max_count && quarantine.count > 0) {
        batch[collected++] = quarantine.ring[quarantine.tail];
        quarantine.tail = (quarantine.tail + 1) % quarantine.capacity;
        quarantine.count--;
    }

    return collected;
}

/*
 * Release collected entries (called without lock held).
 */
static void release_evict_batch(alloc_entry_t **batch, size_t count) {
    for (size_t i = 0; i < count; i++) {
        alloc_entry_t *old = batch[i];

        TRACE("quarantine evict %p (size=%zu)", old->user_addr, old->real_size);

        registry_remove(old->user_addr);
        real_munmap(old->real_addr, old->real_size);
        registry_free_entry(old);
    }
}

void quarantine_add(alloc_entry_t *entry) {
    if (!quarantine.ring || quarantine.capacity == 0) {
        /* Quarantine disabled - release immediately */
        registry_remove(entry->user_addr);
        real_munmap(entry->real_addr, entry->real_size);
        registry_free_entry(entry);
        return;
    }

    /* Mark entire allocation as guard (any access will SIGSEGV) */
    guard_install(entry->real_addr, entry->real_size);

    alloc_entry_t *evict_batch[EVICT_BATCH_SIZE];
    size_t evict_count = 0;

    pthread_mutex_lock(&quarantine.lock);

    /* Evict if full */
    if (quarantine.count >= quarantine.capacity) {
        evict_count = collect_evict_batch(evict_batch, EVICT_BATCH_SIZE);
    }

    /* Add to ring */
    quarantine.ring[quarantine.head] = entry;
    quarantine.head = (quarantine.head + 1) % quarantine.capacity;
    quarantine.count++;

    pthread_mutex_unlock(&quarantine.lock);

    /* Release evicted entries outside the lock */
    if (evict_count > 0) {
        release_evict_batch(evict_batch, evict_count);
    }
}

void quarantine_drain(void) {
    if (!quarantine.ring) return;

    alloc_entry_t *evict_batch[EVICT_BATCH_SIZE];
    size_t evict_count;

    do {
        pthread_mutex_lock(&quarantine.lock);
        evict_count = collect_evict_batch(evict_batch, EVICT_BATCH_SIZE);
        pthread_mutex_unlock(&quarantine.lock);

        release_evict_batch(evict_batch, evict_count);
    } while (evict_count > 0);
}
