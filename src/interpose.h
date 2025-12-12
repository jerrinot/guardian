#ifndef MGUARD_INTERPOSE_H
#define MGUARD_INTERPOSE_H

#include <stddef.h>
#include <sys/types.h>

/* Real function pointers (resolved via dlsym) */
typedef void *(*real_malloc_t)(size_t);
typedef void (*real_free_t)(void *);
typedef void *(*real_calloc_t)(size_t, size_t);
typedef void *(*real_realloc_t)(void *, size_t);
typedef void *(*real_memalign_t)(size_t, size_t);
typedef void *(*real_mmap_t)(void *, size_t, int, int, int, off_t);
typedef int (*real_munmap_t)(void *, size_t);
typedef void *(*real_mremap_t)(void *, size_t, size_t, int, ...);

extern real_malloc_t real_malloc;
extern real_free_t real_free;
extern real_calloc_t real_calloc;
extern real_realloc_t real_realloc;
extern real_memalign_t real_memalign;
extern real_mmap_t real_mmap;
extern real_munmap_t real_munmap;
extern real_mremap_t real_mremap;

/* Global state (defined in mguard.c) */
extern int g_mguard_initialized;
extern __thread int g_in_mguard;

/*
 * Initialize interposition - resolve real functions via dlsym.
 * Must be called early in library initialization.
 */
void interpose_init(void);

#endif /* MGUARD_INTERPOSE_H */
