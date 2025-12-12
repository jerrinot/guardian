#include "registry.h"
#include "config.h"
#include "interpose.h"
#include <sys/mman.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>

#define REGISTRY_BUCKETS 4096
#define REGISTRY_BUCKET_MASK (REGISTRY_BUCKETS - 1)
#define ENTRY_POOL_CHUNK 65536UL  /* Entries per chunk */

/* Hash table buckets */
static alloc_entry_t *buckets[REGISTRY_BUCKETS];
static pthread_mutex_t bucket_locks[REGISTRY_BUCKETS];

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

static inline size_t hash_addr(void *addr) {
    uintptr_t val = (uintptr_t)addr;
    /* Mix bits for better distribution */
    val = (val >> 4) ^ (val >> 12) ^ (val >> 20);
    return val & REGISTRY_BUCKET_MASK;
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
    /* Initialize bucket locks */
    for (size_t i = 0; i < REGISTRY_BUCKETS; i++) {
        pthread_mutex_init(&bucket_locks[i], NULL);
        buckets[i] = NULL;
    }

    pool_chunks = NULL;
    free_list = NULL;

    /* Allocate initial chunk */
    grow_pool();

    atomic_store(&active_count, 0);
    atomic_store(&active_bytes, 0);
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
    pthread_mutex_unlock(&bucket_locks[bucket]);

    atomic_fetch_add(&active_count, 1);
    atomic_fetch_add(&active_bytes, entry->real_size);
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
    for (size_t i = 0; i < REGISTRY_BUCKETS; i++) {
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
