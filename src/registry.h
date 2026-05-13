#ifndef MGUARD_REGISTRY_H
#define MGUARD_REGISTRY_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdatomic.h>

#define MAGIC_ALIVE 0xA11CE001
#define MAGIC_FREED 0xDEAD0001
#define MAGIC_FREEING 0xFEE10001
#define MAGIC_REALLOCING 0xA110C001
#define MGUARD_INTERNAL __attribute__((visibility("hidden")))

#if ATOMIC_POINTER_LOCK_FREE != 2 || ATOMIC_INT_LOCK_FREE != 2
#error "mguard requires always-lock-free pointer and int atomics"
#endif

typedef enum {
    ALLOC_MALLOC,
    ALLOC_CALLOC,
    ALLOC_REALLOC,
    ALLOC_MEMALIGN,
    ALLOC_MMAP_ANON,
    ALLOC_MMAP_FILE
} alloc_type_t;

typedef enum {
    REGISTRY_CLAIM_NOT_FOUND,
    REGISTRY_CLAIMED,
    REGISTRY_CLAIM_ALREADY_FREED
} registry_claim_result_t;

typedef struct alloc_entry {
    void *user_addr;           /* Address returned to application */
    void *real_addr;           /* Actual mmap base */
    size_t user_size;          /* Requested size */
    size_t real_size;          /* Actual allocation span tracked for release */
    size_t guard_size;         /* Guard bytes included in real_size */
    size_t pre_padding;        /* Bytes of padding before user_addr */
    size_t post_padding;       /* Bytes of padding after user data */
    alloc_type_t type;
    int prot;                  /* mmap protection */
    int flags;                 /* mmap flags */
    int fd;                    /* File descriptor (-1 for malloc/anon) */
    off_t offset;              /* File offset */
    _Atomic uint32_t magic;    /* MAGIC_* allocation state */
    _Atomic(struct alloc_entry *) next;  /* Hash chain */
    struct alloc_entry *free_next;       /* Entry pool free-list chain */
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
 * Atomically claim a live entry for free/munmap while holding its bucket lock.
 * REGISTRY_CLAIM_ALREADY_FREED returns with the entry read-side guard held;
 * callers must either abort while reporting or call registry_signal_read_end().
 */
registry_claim_result_t registry_claim_free(void *user_addr, alloc_entry_t **entry_out);

/*
 * Restore an entry claimed by registry_claim_free() when the caller decides
 * not to release it after all.
 */
void registry_unclaim_free(alloc_entry_t *entry);

/*
 * Atomically claim a live entry for realloc while holding its bucket lock.
 * REGISTRY_CLAIM_ALREADY_FREED returns with the entry read-side guard held;
 * callers must either abort while reporting or call registry_signal_read_end().
 */
registry_claim_result_t registry_claim_realloc(void *user_addr, alloc_entry_t **entry_out);

/*
 * Restore an entry claimed by registry_claim_realloc() after allocation failure.
 */
void registry_unclaim_realloc(alloc_entry_t *entry);

/*
 * Look up an entry containing the given address.
 * Returns NULL if address is not within any known allocation.
 */
alloc_entry_t *registry_lookup_containing(void *addr);

/*
 * Entry read-side guard. Keep this held while using entries returned by
 * registry_lookup_containing_signal(), or already-freed entries returned for
 * double-free reporting.
 */
MGUARD_INTERNAL void registry_signal_read_begin(void);
MGUARD_INTERNAL void registry_signal_read_end(void);

/*
 * Signal-safe containing-address lookup. Caller must hold
 * registry_signal_read_begin()/end().
 */
MGUARD_INTERNAL alloc_entry_t *registry_lookup_containing_signal(void *addr);

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
