#ifndef MGUARD_REGISTRY_H
#define MGUARD_REGISTRY_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <pthread.h>

#define MAGIC_ALIVE 0xA11CE001
#define MAGIC_FREED 0xDEAD0001

typedef enum {
    ALLOC_MALLOC,
    ALLOC_CALLOC,
    ALLOC_REALLOC,
    ALLOC_MEMALIGN,
    ALLOC_MMAP_ANON,
    ALLOC_MMAP_FILE
} alloc_type_t;

typedef struct alloc_entry {
    void *user_addr;           /* Address returned to application */
    void *real_addr;           /* Actual mmap base */
    size_t user_size;          /* Requested size */
    size_t real_size;          /* Actual allocation (with guard page) */
    size_t pre_padding;        /* Bytes of padding before user_addr */
    size_t post_padding;       /* Bytes of padding after user data */
    alloc_type_t type;
    int prot;                  /* mmap protection */
    int flags;                 /* mmap flags */
    int fd;                    /* File descriptor (-1 for malloc/anon) */
    off_t offset;              /* File offset */
    uint32_t magic;            /* MAGIC_ALIVE or MAGIC_FREED */
    struct alloc_entry *next;  /* Hash chain */
} alloc_entry_t;

/*
 * Initialize the registry. Must be called before any other registry functions.
 * Uses mmap directly for entry pool (no malloc dependency).
 */
void registry_init(void);

/*
 * Allocate an entry from the pool.
 * Returns NULL if pool exhausted.
 */
alloc_entry_t *registry_alloc_entry(void);

/*
 * Return an entry to the pool.
 */
void registry_free_entry(alloc_entry_t *entry);

/*
 * Insert an entry into the registry.
 * Entry must have user_addr set.
 */
void registry_insert(alloc_entry_t *entry);

/*
 * Look up an entry by exact user address.
 * Returns NULL if not found.
 */
alloc_entry_t *registry_lookup(void *user_addr);

/*
 * Look up an entry containing the given address.
 * Returns NULL if address is not within any known allocation.
 */
alloc_entry_t *registry_lookup_containing(void *addr);

/*
 * Remove and return an entry by exact user address.
 * Returns NULL if not found.
 */
alloc_entry_t *registry_remove(void *user_addr);

/*
 * Get current registry statistics.
 */
size_t registry_get_count(void);
size_t registry_get_bytes(void);

#endif /* MGUARD_REGISTRY_H */
