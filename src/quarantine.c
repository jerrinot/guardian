#include "quarantine.h"
#include "registry.h"
#include "config.h"
#include "guard.h"
#include "interpose.h"
#include <pthread.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <stdio.h>

#define TRACE(fmt, ...) \
    do { \
        if (g_config.verbose) { \
            fprintf(stderr, "[mguard] " fmt "\n", ##__VA_ARGS__); \
        } \
    } while (0)

#define QUARANTINE_RING_SIZE 65536

typedef struct {
    alloc_entry_t **ring;
    size_t capacity;
    size_t head;
    size_t tail;
    atomic_size_t bytes;
    pthread_mutex_t lock;
} quarantine_t;

static quarantine_t quarantine;

void quarantine_init(void) {
    if (g_config.quarantine_bytes == 0) {
        quarantine.ring = NULL;
        quarantine.capacity = 0;
        return;
    }

    /* Allocate ring buffer via mmap to avoid malloc recursion */
    size_t ring_bytes = QUARANTINE_RING_SIZE * sizeof(alloc_entry_t *);
    quarantine.ring = real_mmap(NULL, ring_bytes, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (quarantine.ring == MAP_FAILED) {
        quarantine.ring = NULL;
        quarantine.capacity = 0;
        return;
    }

    quarantine.capacity = QUARANTINE_RING_SIZE;
    quarantine.head = 0;
    quarantine.tail = 0;
    atomic_store(&quarantine.bytes, 0);
    pthread_mutex_init(&quarantine.lock, NULL);
}

static void evict_oldest(void) {
    if (quarantine.head == quarantine.tail) {
        return; /* Empty */
    }

    alloc_entry_t *old = quarantine.ring[quarantine.tail];
    quarantine.tail = (quarantine.tail + 1) % quarantine.capacity;
    size_t old_bytes = atomic_fetch_sub(&quarantine.bytes, old->real_size);

    TRACE("quarantine evict %p (size=%zu, quarantine_bytes=%zu->%zu)",
          old->user_addr, old->real_size, old_bytes, old_bytes - old->real_size);

    /* Remove from registry (entry was kept there for double-free detection) */
    registry_remove(old->user_addr);

    /* Release the memory */
    real_munmap(old->real_addr, old->real_size);
    registry_free_entry(old);
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

    pthread_mutex_lock(&quarantine.lock);

    /* Evict old entries if over limit */
    while (atomic_load(&quarantine.bytes) + entry->real_size > g_config.quarantine_bytes &&
           quarantine.head != quarantine.tail) {
        evict_oldest();
    }

    /* Check if ring is full */
    size_t next_head = (quarantine.head + 1) % quarantine.capacity;
    if (next_head == quarantine.tail) {
        evict_oldest();
    }

    /* Add to ring */
    quarantine.ring[quarantine.head] = entry;
    quarantine.head = next_head;
    atomic_fetch_add(&quarantine.bytes, entry->real_size);

    pthread_mutex_unlock(&quarantine.lock);
}

void quarantine_drain(void) {
    if (!quarantine.ring) return;

    pthread_mutex_lock(&quarantine.lock);

    while (quarantine.head != quarantine.tail) {
        evict_oldest();
    }

    pthread_mutex_unlock(&quarantine.lock);
}
