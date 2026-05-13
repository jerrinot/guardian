#ifndef MGUARD_INTERPOSE_H
#define MGUARD_INTERPOSE_H

#include <stddef.h>
#include <stdatomic.h>
#include <sys/types.h>

/* Real function pointers (resolved via dlsym) */
typedef void *(*real_malloc_t)(size_t);
typedef void (*real_free_t)(void *);
typedef void *(*real_calloc_t)(size_t, size_t);
typedef void *(*real_realloc_t)(void *, size_t);
typedef void *(*real_memalign_t)(size_t, size_t);
typedef int (*real_posix_memalign_t)(void **, size_t, size_t);
typedef void *(*real_aligned_alloc_t)(size_t, size_t);
typedef void *(*real_valloc_t)(size_t);
typedef void *(*real_mmap_t)(void *, size_t, int, int, int, off_t);
typedef int (*real_munmap_t)(void *, size_t);
typedef void *(*real_mremap_t)(void *, size_t, size_t, int, ...);

extern real_malloc_t real_malloc;
extern real_free_t real_free;
extern real_calloc_t real_calloc;
extern real_realloc_t real_realloc;
extern real_memalign_t real_memalign;
extern real_posix_memalign_t real_posix_memalign;
extern real_aligned_alloc_t real_aligned_alloc;
extern real_valloc_t real_valloc;
extern real_mmap_t real_mmap;
extern real_munmap_t real_munmap;
extern real_mremap_t real_mremap;

/* Global state (defined in mguard.c) */
extern _Atomic int g_mguard_initialized;
extern int g_mguard_jvm_mode;
extern __thread int g_in_mguard;

static inline int mguard_is_initialized(void) {
    return atomic_load_explicit(&g_mguard_initialized, memory_order_acquire);
}

/*
 * Initialize interposition - resolve real functions via dlsym.
 * Must be called early in library initialization.
 */
void interpose_init(void);

int mguard_has_jvm_wrapper(void);

#endif /* MGUARD_INTERPOSE_H */
