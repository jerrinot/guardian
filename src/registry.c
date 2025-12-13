/*
 * registry.c - Hash table tracking all mguard-managed allocations
 *
 * DATA STRUCTURE LAYOUT
 * =====================
 *
 * Hash Table (separate chaining):
 *
 *   buckets[] (dynamically allocated, default 65536 slots via MGUARD_BUCKETS)
 *   ┌─────────┬─────────┬─────────┬─────────┬─────────┐
 *   │    0    │    1    │    2    │   ...   │  65535  │
 *   └────┬────┴────┬────┴────┬────┴─────────┴────┬────┘
 *        │         │         │                   │
 *        ▼         ▼         ▼                   ▼
 *      NULL    ┌───────┐   NULL              ┌───────┐
 *              │ entry │                     │ entry │
 *              │ next ─┼─► NULL              │ next ─┼─► entry ─► NULL
 *              └───────┘                     └───────┘
 *
 *   bucket_locks[] (parallel array, one mutex per bucket for fine-grained locking)
 *
 * Entry Pool (avoids malloc recursion):
 *
 *   pool_chunks: linked list of mmap'd chunks, each holding 65536 entries
 *   ┌────────────┐     ┌────────────┐
 *   │ pool_chunk │ ──► │ pool_chunk │ ──► NULL
 *   │ entries[]  │     │ entries[]  │
 *   └────────────┘     └────────────┘
 *
 *   free_list: LIFO stack of unused entries (reuses 'next' pointer)
 *
 * OPERATIONS
 * ==========
 *   registry_insert()           O(1)           bucket_locks[hash]
 *   registry_lookup()           O(chain_len)   bucket_locks[hash]
 *   registry_remove()           O(chain_len)   bucket_locks[hash]
 *   registry_lookup_containing() O(n×chain)    all locks (signal handler only)
 *   registry_alloc_entry()      O(1)           pool_lock
 *   registry_free_entry()       O(1)           pool_lock
 *
 * HASH FUNCTION
 * =============
 *   hash = ((addr >> 4) ^ (addr >> 12) ^ (addr >> 20)) & (buckets - 1)
 *
 *   Skips low 4 bits (16-byte alignment) and mixes higher bits for
 *   better distribution across buckets.
 */

#include "registry.h"
#include "config.h"
#include "interpose.h"
#include <sys/mman.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>

#define ENTRY_POOL_CHUNK 65536UL  /* Entries per chunk */
#define REGISTRY_LOAD_WARN_THRESHOLD 4  /* Warn when chain length exceeds this */

/* Hash table buckets - dynamically allocated based on MGUARD_BUCKETS */
static alloc_entry_t **buckets;
static pthread_mutex_t *bucket_locks;

/* Entry pool chunks (linked list of mmap'd chunks) */
typedef struct pool_chunk {
    struct pool_chunk *next;
    size_t capacity;
    alloc_entry_t entries[];
} pool_chunk_t;

static pool_chunk_t *pool_chunks;
static alloc_entry_t *free_list;
static pthread_mutex_t pool_lock = PTHREAD_MUTEX_INITIALIZER;

/* Statistics */
static atomic_size_t active_count;
static atomic_size_t active_bytes;
static int load_warning_printed;

static inline size_t hash_addr(void *addr) {
    uintptr_t val = (uintptr_t)addr;
    /* Mix bits for better distribution */
    val = (val >> 4) ^ (val >> 12) ^ (val >> 20);
    return val & (g_config.registry_buckets - 1);
}

/*
 * Allocate a new chunk of entries and add to free list.
 * Must be called with pool_lock held.
 * Uses real_mmap to avoid recursion.
 */
static int grow_pool(void) {
    size_t chunk_bytes = sizeof(pool_chunk_t) + ENTRY_POOL_CHUNK * sizeof(alloc_entry_t);

    pool_chunk_t *chunk = real_mmap(NULL, chunk_bytes, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (chunk == MAP_FAILED) {
        return 0;
    }

    chunk->capacity = ENTRY_POOL_CHUNK;
    chunk->next = pool_chunks;
    pool_chunks = chunk;

    /* Add all entries to free list */
    for (size_t i = 0; i < ENTRY_POOL_CHUNK - 1; i++) {
        chunk->entries[i].next = &chunk->entries[i + 1];
    }
    chunk->entries[ENTRY_POOL_CHUNK - 1].next = free_list;
    free_list = &chunk->entries[0];

    if (g_config.verbose) {
        fprintf(stderr, "[mguard] registry: allocated new chunk (%zu entries)\n", ENTRY_POOL_CHUNK);
    }

    return 1;
}

void registry_init(void) {
    size_t num_buckets = g_config.registry_buckets;

    /* Allocate bucket arrays via mmap to avoid malloc recursion */
    size_t buckets_bytes = num_buckets * sizeof(alloc_entry_t *);
    size_t locks_bytes = num_buckets * sizeof(pthread_mutex_t);

    buckets = real_mmap(NULL, buckets_bytes, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    bucket_locks = real_mmap(NULL, locks_bytes, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (buckets == MAP_FAILED || bucket_locks == MAP_FAILED) {
        fprintf(stderr, "[mguard] FATAL: failed to allocate registry buckets\n");
        return;
    }

    /* Initialize bucket locks */
    for (size_t i = 0; i < num_buckets; i++) {
        pthread_mutex_init(&bucket_locks[i], NULL);
        buckets[i] = NULL;
    }

    pool_chunks = NULL;
    free_list = NULL;

    /* Allocate initial chunk */
    grow_pool();

    atomic_store(&active_count, 0);
    atomic_store(&active_bytes, 0);

    if (g_config.verbose) {
        fprintf(stderr, "[mguard] registry: %zu buckets allocated\n", num_buckets);
    }
}

alloc_entry_t *registry_alloc_entry(void) {
    pthread_mutex_lock(&pool_lock);

    if (!free_list) {
        /* Pool exhausted - grow it */
        if (!grow_pool()) {
            pthread_mutex_unlock(&pool_lock);
            return NULL;
        }
    }

    alloc_entry_t *entry = free_list;
    free_list = entry->next;

    pthread_mutex_unlock(&pool_lock);

    /* Clear the entry */
    memset(entry, 0, sizeof(*entry));
    return entry;
}

void registry_free_entry(alloc_entry_t *entry) {
    if (!entry) return;

    pthread_mutex_lock(&pool_lock);
    entry->next = free_list;
    free_list = entry;
    pthread_mutex_unlock(&pool_lock);
}

void registry_insert(alloc_entry_t *entry) {
    if (!entry || !entry->user_addr) return;

    size_t bucket = hash_addr(entry->user_addr);

    pthread_mutex_lock(&bucket_locks[bucket]);
    entry->next = buckets[bucket];
    buckets[bucket] = entry;

    /* Count chain length while we have the lock */
    size_t chain_len = 0;
    for (alloc_entry_t *e = buckets[bucket]; e; e = e->next) chain_len++;

    pthread_mutex_unlock(&bucket_locks[bucket]);

    atomic_fetch_add(&active_count, 1);
    atomic_fetch_add(&active_bytes, entry->real_size);

    /* Warn once if any chain gets too long */
    if (!load_warning_printed && chain_len > REGISTRY_LOAD_WARN_THRESHOLD) {
        load_warning_printed = 1;
        fprintf(stderr, "[mguard] WARNING: registry chain length %zu exceeds threshold %d. "
                "Performance may degrade. Consider setting MGUARD_BUCKETS=%zu or higher.\n",
                chain_len, REGISTRY_LOAD_WARN_THRESHOLD, g_config.registry_buckets * 4);
    }
}

alloc_entry_t *registry_lookup(void *user_addr) {
    if (!user_addr) return NULL;

    size_t bucket = hash_addr(user_addr);

    pthread_mutex_lock(&bucket_locks[bucket]);
    alloc_entry_t *entry = buckets[bucket];
    while (entry) {
        if (entry->user_addr == user_addr) {
            pthread_mutex_unlock(&bucket_locks[bucket]);
            return entry;
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&bucket_locks[bucket]);

    return NULL;
}

alloc_entry_t *registry_lookup_containing(void *addr) {
    if (!addr) return NULL;

    /* Must scan all buckets - this is slow but only used in signal handler */
    for (size_t i = 0; i < g_config.registry_buckets; i++) {
        pthread_mutex_lock(&bucket_locks[i]);
        alloc_entry_t *entry = buckets[i];
        while (entry) {
            uintptr_t base = (uintptr_t)entry->real_addr;
            uintptr_t end = base + entry->real_size;
            uintptr_t target = (uintptr_t)addr;

            if (target >= base && target < end) {
                pthread_mutex_unlock(&bucket_locks[i]);
                return entry;
            }
            entry = entry->next;
        }
        pthread_mutex_unlock(&bucket_locks[i]);
    }

    return NULL;
}

alloc_entry_t *registry_remove(void *user_addr) {
    if (!user_addr) return NULL;

    size_t bucket = hash_addr(user_addr);

    pthread_mutex_lock(&bucket_locks[bucket]);
    alloc_entry_t **pp = &buckets[bucket];
    while (*pp) {
        if ((*pp)->user_addr == user_addr) {
            alloc_entry_t *entry = *pp;
            *pp = entry->next;
            entry->next = NULL;
            pthread_mutex_unlock(&bucket_locks[bucket]);

            atomic_fetch_sub(&active_count, 1);
            atomic_fetch_sub(&active_bytes, entry->real_size);
            return entry;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&bucket_locks[bucket]);

    return NULL;
}

size_t registry_get_count(void) {
    return atomic_load(&active_count);
}

size_t registry_get_bytes(void) {
    return atomic_load(&active_bytes);
}
