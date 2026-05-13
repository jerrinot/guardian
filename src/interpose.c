#define _GNU_SOURCE
#include "interpose.h"
#include "config.h"
#include "registry.h"
#include "quarantine.h"
#include "guard.h"
#include "report.h"
#include <dlfcn.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

/* Debug tracing macro */
#define TRACE(fmt, ...) \
    do { \
        if (g_config.verbose) { \
            fprintf(stderr, "[mguard] " fmt "\n", ##__VA_ARGS__); \
        } \
    } while (0)

/* Alignment macros */
#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((align) - 1))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

/* Malloc alignment requirement (16 bytes on x64 for SIMD/AVX) */
#define MALLOC_ALIGNMENT 16

static int checked_align_up(size_t value, size_t alignment, size_t *out) {
    size_t rounded;

    if (alignment == 0) {
        return -1;
    }
    if (__builtin_add_overflow(value, alignment - 1, &rounded)) {
        return -1;
    }

    *out = rounded & ~(alignment - 1);
    return 0;
}

/* Real function pointers */
real_malloc_t real_malloc = NULL;
real_free_t real_free = NULL;
real_calloc_t real_calloc = NULL;
real_realloc_t real_realloc = NULL;
real_memalign_t real_memalign = NULL;
real_posix_memalign_t real_posix_memalign = NULL;
real_aligned_alloc_t real_aligned_alloc = NULL;
real_valloc_t real_valloc = NULL;
real_mmap_t real_mmap = NULL;
real_munmap_t real_munmap = NULL;
real_mremap_t real_mremap = NULL;


/*
 * Bootstrap allocator for early allocations during dlsym resolution.
 * dlsym can call calloc/malloc internally, so we need this to break
 * the infinite recursion. Size needs to be large enough for system
 * libraries (GnuTLS, etc.) that initialize during library load.
 */
static char bootstrap_buf[262144];  /* 256KB */
static atomic_size_t bootstrap_pos;

static void *bootstrap_alloc(size_t size) {
    size_t aligned;
    if (checked_align_up(size, MALLOC_ALIGNMENT, &aligned) != 0) {
        fprintf(stderr, "[mguard] bootstrap_alloc(%zu): FAILED (size overflow)\n", size);
        errno = ENOMEM;
        return NULL;
    }

    if (aligned > sizeof(bootstrap_buf)) {
        fprintf(stderr, "[mguard] bootstrap_alloc(%zu): FAILED (buffer full)\n", size);
        errno = ENOMEM;
        return NULL;
    }

    size_t pos = atomic_load_explicit(&bootstrap_pos, memory_order_relaxed);
    for (;;) {
        if (pos > sizeof(bootstrap_buf) - aligned) {
            fprintf(stderr, "[mguard] bootstrap_alloc(%zu): FAILED (buffer full)\n", size);
            errno = ENOMEM;
            return NULL;
        }
        size_t new_pos = pos + aligned;
        if (atomic_compare_exchange_weak_explicit(&bootstrap_pos, &pos,
                                                  new_pos,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed)) {
            break;
        }
    }

    void *p = bootstrap_buf + pos;
    memset(p, 0, aligned);
    fprintf(stderr, "[mguard] bootstrap_alloc(%zu) = %p (pos=%zu)\n",
            size, p, pos + aligned);
    return p;
}

static int is_bootstrap_ptr(void *ptr) {
    uintptr_t p = (uintptr_t)ptr;
    uintptr_t base = (uintptr_t)bootstrap_buf;
    return (p >= base && p < base + sizeof(bootstrap_buf));
}

void interpose_init(void) {
    /*
     * Use dlsym to find the real implementations.
     * POSIX allows converting void* from dlsym to function pointers,
     * but ISO C forbids it. Use the POSIX-recommended cast pattern.
     */
    *(void **)(&real_malloc) = dlsym(RTLD_NEXT, "malloc");
    *(void **)(&real_free) = dlsym(RTLD_NEXT, "free");
    *(void **)(&real_calloc) = dlsym(RTLD_NEXT, "calloc");
    *(void **)(&real_realloc) = dlsym(RTLD_NEXT, "realloc");
    *(void **)(&real_memalign) = dlsym(RTLD_NEXT, "memalign");
    *(void **)(&real_posix_memalign) = dlsym(RTLD_NEXT, "posix_memalign");
    *(void **)(&real_aligned_alloc) = dlsym(RTLD_NEXT, "aligned_alloc");
    *(void **)(&real_valloc) = dlsym(RTLD_NEXT, "valloc");
    *(void **)(&real_mmap) = dlsym(RTLD_NEXT, "mmap");
    *(void **)(&real_munmap) = dlsym(RTLD_NEXT, "munmap");
    *(void **)(&real_mremap) = dlsym(RTLD_NEXT, "mremap");
}

/*
 * Verify padding pattern to detect overflow on free.
 * Returns 1 if padding is intact, 0 if corrupted.
 */
static int verify_padding(alloc_entry_t *entry) {
    if (entry->type == ALLOC_MMAP_FILE) {
        /* File-backed mappings don't have byte-level padding */
        return 1;
    }

    /* Check pre-padding (between real_addr and user_addr) */
    if (entry->pre_padding > 0) {
        unsigned char *pre = (unsigned char *)entry->real_addr;
        for (size_t i = 0; i < entry->pre_padding; i++) {
            if (pre[i] != g_config.fill_pattern) {
                return 0;
            }
        }
    }

    /* Check post-padding (between user data end and guard page) */
    if (entry->post_padding > 0) {
        unsigned char *post = (unsigned char *)entry->user_addr + entry->user_size;
        for (size_t i = 0; i < entry->post_padding; i++) {
            if (post[i] != g_config.fill_pattern) {
                return 0;
            }
        }
    }

    return 1;
}

static int is_mmap_entry(const alloc_entry_t *entry) {
    return entry->type == ALLOC_MMAP_ANON || entry->type == ALLOC_MMAP_FILE;
}

static size_t mapped_user_span(const alloc_entry_t *entry) {
    if (!is_mmap_entry(entry) || entry->real_size < entry->guard_size) {
        return entry->user_size;
    }
    return entry->real_size - entry->guard_size;
}

static int tracked_length_matches(const alloc_entry_t *entry, size_t length) {
    return length == entry->user_size ||
           (is_mmap_entry(entry) && length == mapped_user_span(entry));
}

static size_t munmap_prefix_release_size(const alloc_entry_t *entry,
                                         size_t unmap_len) {
    if (g_config.protect_below && is_mmap_entry(entry)) {
        return unmap_len + entry->guard_size;
    }
    return unmap_len;
}

static void release_claimed_entry(void *ptr, alloc_entry_t *entry) {
    /* Verify padding (detect overflow on free) */
    if (!verify_padding(entry)) {
        report_overflow_on_free(ptr, entry);
        /* report_overflow_on_free calls abort() */
    }

    atomic_store_explicit(&entry->magic, MAGIC_FREEING, memory_order_release);

    /* Add to quarantine or release immediately */
    if (g_config.quarantine_entries > 0) {
        /*
         * Keep entry in registry for double-free detection.
         * Publish MAGIC_FREED only after the region is guarded so a stale
         * access after the freed state is visible will fault as UAF.
         */
        TRACE("release(%p) -> quarantine", ptr);
        guard_install(entry->real_addr, entry->real_size);
        atomic_store_explicit(&entry->magic, MAGIC_FREED, memory_order_release);
        quarantine_add(entry);
    } else {
        /* No quarantine - remove and release immediately */
        TRACE("release(%p) -> munmap immediately", ptr);
        atomic_store_explicit(&entry->magic, MAGIC_FREED, memory_order_release);
        registry_remove(ptr);
        real_munmap(entry->real_addr, entry->real_size);
        registry_free_entry(entry);
    }
}

static int release_claimed_mmap_entry(void *addr, alloc_entry_t *entry) {
    if (entry->type == ALLOC_MMAP_ANON && !verify_padding(entry)) {
        report_overflow_on_free(addr, entry);
        /* report_overflow_on_free calls abort() */
    }

    registry_remove(addr);
    int result = real_munmap(entry->real_addr, entry->real_size);
    registry_free_entry(entry);
    return result;
}

/*
 * Register a new allocation in the registry.
 */
static void register_alloc(void *user_ptr, void *real_ptr, size_t user_size,
                          size_t real_size, size_t pre_padding, size_t post_padding,
                          alloc_type_t type, int prot, int flags, int fd, off_t offset) {
    alloc_entry_t *entry = registry_alloc_entry();
    if (!entry) {
        /* This should never happen now that pool grows, but just in case */
        fprintf(stderr, "[mguard] FATAL: registry_alloc_entry failed (out of memory?)\n");
        return;
    }

    entry->user_addr = user_ptr;
    entry->real_addr = real_ptr;
    entry->user_size = user_size;
    entry->real_size = real_size;
    entry->guard_size = g_config.page_size;
    entry->pre_padding = pre_padding;
    entry->post_padding = post_padding;
    entry->type = type;
    entry->prot = prot;
    entry->flags = flags;
    entry->fd = fd;
    entry->offset = offset;
    atomic_store_explicit(&entry->magic, MAGIC_ALIVE, memory_order_release);

    registry_insert(entry);

    TRACE("registered %p (entry=%p, count=%zu, bytes=%zu)",
          user_ptr, (void*)entry, registry_get_count(), registry_get_bytes());
}

/* ========== MALLOC FAMILY ========== */

void *malloc(size_t size) {
    /* Bootstrap path - before dlsym resolves */
    if (!real_malloc) {
        return bootstrap_alloc(size);
    }

    /* Fast path - recursion guard or disabled */
    if (g_in_mguard || !mguard_is_initialized() || !g_config.enabled) {
        void *p = real_malloc(size);
        TRACE("malloc(%zu) = %p [real, in_mguard=%d init=%d enabled=%d]",
              size, p, g_in_mguard, mguard_is_initialized(), g_config.enabled);
        return p;
    }

    /* Handle zero-size allocations - delegate to real malloc.
     * C standard allows malloc(0) to return NULL or a unique pointer.
     * Many programs (including JVM) expect a valid pointer. */
    if (size == 0) {
        void *p = real_malloc(size);
        TRACE("malloc(0) = %p [real, zero-size]", p);
        return p;
    }

    /* Skip small allocations if configured */
    if (size < g_config.min_size) {
        void *p = real_malloc(size);
        TRACE("malloc(%zu) = %p [real, below min_size=%zu]", size, p, g_config.min_size);
        return p;
    }

    g_in_mguard = 1;

    size_t page_size = g_config.page_size;
    /* Align to MALLOC_ALIGNMENT to meet ABI requirements */
    size_t effective;
    size_t aligned;
    size_t total;
    if (checked_align_up(size, MALLOC_ALIGNMENT, &effective) != 0 ||
        checked_align_up(effective, page_size, &aligned) != 0 ||
        __builtin_add_overflow(aligned, page_size, &total)) {
        TRACE("malloc(%zu): size overflow", size);
        g_in_mguard = 0;
        errno = ENOMEM;
        return NULL;
    }

    void *base = real_mmap(NULL, total, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        int saved_errno = errno;
        TRACE("malloc(%zu): mmap failed, errno=%d (%s)", size, saved_errno, strerror(saved_errno));
        g_in_mguard = 0;
        errno = ENOMEM;
        return NULL;
    }

    void *user_ptr;
    void *guard_page;
    size_t pre_padding = 0;
    size_t post_padding = 0;

    if (g_config.protect_below) {
        /* Guard page at start (underflow detection) */
        guard_page = base;
        user_ptr = (char *)base + page_size;
        /* Fill padding after user data */
        post_padding = aligned - size;
        if (post_padding > 0) {
            memset((char *)user_ptr + size, g_config.fill_pattern, post_padding);
        }
    } else {
        /* Guard page at end (overflow detection - default) */
        guard_page = (char *)base + aligned;
        /* Position user pointer so end aligns with guard page */
        pre_padding = aligned - effective;
        user_ptr = (char *)base + pre_padding;
        /* Post padding = gap between user data end and guard page */
        post_padding = effective - size;
        /* Fill padding before user data */
        if (pre_padding > 0) {
            memset(base, g_config.fill_pattern, pre_padding);
        }
        /* Fill padding after user data (for overflow detection on free) */
        if (post_padding > 0) {
            memset((char *)user_ptr + size, g_config.fill_pattern, post_padding);
        }
    }

    /* Install guard page */
    if (guard_install(guard_page, page_size) != 0) {
        /* MADV_GUARD failed - release and fall back */
        TRACE("malloc(%zu): guard_install failed, falling back to real_malloc", size);
        real_munmap(base, total);
        g_in_mguard = 0;
        return real_malloc(size);
    }

    register_alloc(user_ptr, base, size, total, pre_padding, post_padding,
                   ALLOC_MALLOC, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    TRACE("malloc(%zu) = %p [guarded, base=%p, total=%zu]", size, user_ptr, base, total);

    g_in_mguard = 0;
    return user_ptr;
}

void free(void *ptr) {
    if (!ptr) return;

    /* Bootstrap allocations are never freed (static buffer) */
    if (is_bootstrap_ptr(ptr)) {
        TRACE("free(%p) [bootstrap, ignored]", ptr);
        return;
    }

    /* Fast path */
    if (!real_free || g_in_mguard || !mguard_is_initialized() || !g_config.enabled) {
        TRACE("free(%p) [real, in_mguard=%d init=%d enabled=%d]",
              ptr, g_in_mguard, mguard_is_initialized(), g_config.enabled);
        if (real_free) real_free(ptr);
        return;
    }

    g_in_mguard = 1;

    TRACE("free(%p): looking up in registry...", ptr);
    alloc_entry_t *entry = NULL;
    registry_claim_result_t claim = registry_claim_free(ptr, &entry);
    if (claim == REGISTRY_CLAIM_NOT_FOUND) {
        if (g_config.verbose) {
            /* Only used to make the trace message more specific. */
            registry_signal_read_begin();
            alloc_entry_t *containing = registry_lookup_containing_signal(ptr);
            if (containing) {
                TRACE("free(%p) BUG: not exact match but inside [%p + %zu], calling real_free anyway",
                      ptr, containing->user_addr, containing->user_size);
            } else {
                TRACE("free(%p) NOT FOUND in registry, calling real_free", ptr);
            }
            registry_signal_read_end();
        }
        g_in_mguard = 0;
        real_free(ptr);
        return;
    }

    if (claim == REGISTRY_CLAIM_ALREADY_FREED) {
        report_double_free(ptr, entry);
        registry_signal_read_end();
        /* report_double_free calls abort() */
    }

    TRACE("free(%p) [guarded, base=%p, size=%zu, magic=0x%x]",
          ptr, entry->real_addr, entry->user_size, MAGIC_FREED);

    release_claimed_entry(ptr, entry);

    g_in_mguard = 0;
}

void *calloc(size_t nmemb, size_t size) {
    /* Bootstrap path */
    if (!real_calloc) {
        size_t total;
        if (__builtin_mul_overflow(nmemb, size, &total)) {
            errno = ENOMEM;
            return NULL;
        }
        return bootstrap_alloc(total); /* bootstrap_alloc zeros memory */
    }

    /* Fast path */
    if (g_in_mguard || !mguard_is_initialized() || !g_config.enabled) {
        void *p = real_calloc(nmemb, size);
        TRACE("calloc(%zu, %zu) = %p [real]", nmemb, size, p);
        return p;
    }

    /* Check for overflow */
    size_t total;
    if (__builtin_mul_overflow(nmemb, size, &total)) {
        TRACE("calloc(%zu, %zu): overflow", nmemb, size);
        errno = ENOMEM;
        return NULL;
    }

    void *ptr = malloc(total);
    if (ptr) {
        memset(ptr, 0, total);
    }
    TRACE("calloc(%zu, %zu) = %p", nmemb, size, ptr);
    return ptr;
}

void *realloc(void *ptr, size_t size) {
    if (!ptr) {
        if (real_realloc && (g_in_mguard || !mguard_is_initialized() || !g_config.enabled)) {
            void *p = real_realloc(NULL, size);
            TRACE("realloc(NULL, %zu) = %p [real]", size, p);
            return p;
        }
        TRACE("realloc(NULL, %zu) -> malloc", size);
        return malloc(size);
    }

    /* Bootstrap pointers can't be reallocated properly */
    if (is_bootstrap_ptr(ptr)) {
        if (size == 0) {
            TRACE("realloc(%p, 0) -> free [bootstrap]", ptr);
            free(ptr);
            return NULL;
        }
        TRACE("realloc(%p, %zu) = NULL [bootstrap, unsupported]", ptr, size);
        errno = ENOMEM;
        return NULL;
    }

    /* Fast path */
    if (!real_realloc || g_in_mguard || !mguard_is_initialized() || !g_config.enabled) {
        void *p = real_realloc ? real_realloc(ptr, size) : NULL;
        TRACE("realloc(%p, %zu) = %p [real]", ptr, size, p);
        return p;
    }

    if (size == 0) {
        TRACE("realloc(%p, 0) -> free", ptr);
        free(ptr);
        return NULL;
    }

    g_in_mguard = 1;

    alloc_entry_t *entry = NULL;
    registry_claim_result_t claim = registry_claim_realloc(ptr, &entry);
    if (claim == REGISTRY_CLAIM_NOT_FOUND) {
        g_in_mguard = 0;
        void *p = real_realloc(ptr, size);
        TRACE("realloc(%p, %zu) = %p [real, not in registry]", ptr, size, p);
        return p;
    }

    if (claim == REGISTRY_CLAIM_ALREADY_FREED) {
        report_realloc_freed(ptr, entry);
        registry_signal_read_end();
        /* report_realloc_freed calls abort() */
    }

    size_t old_size = entry->user_size;
    TRACE("realloc(%p, %zu) [guarded, old_size=%zu]", ptr, size, old_size);

    g_in_mguard = 0;

    /* Allocate and copy while the old entry is claimed against concurrent free. */
    void *new_ptr = malloc(size);
    if (!new_ptr) {
        registry_unclaim_realloc(entry);
        return NULL;
    }

    memcpy(new_ptr, ptr, MIN(old_size, size));

    TRACE("realloc(%p, %zu) = %p [guarded, releasing old]", ptr, size, new_ptr);
    g_in_mguard = 1;
    release_claimed_entry(ptr, entry);
    g_in_mguard = 0;

    return new_ptr;
}

void *memalign(size_t alignment, size_t size) {
    /* Fast path */
    if (!real_memalign || g_in_mguard || !mguard_is_initialized() || !g_config.enabled) {
        void *p = real_memalign ? real_memalign(alignment, size) : NULL;
        TRACE("memalign(%zu, %zu) = %p [real]", alignment, size, p);
        return p;
    }

    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        TRACE("memalign(%zu, %zu): invalid alignment", alignment, size);
        errno = EINVAL;
        return NULL;
    }

    /* Handle zero-size - delegate to real memalign */
    if (size == 0) {
        void *p = real_memalign(alignment, size);
        TRACE("memalign(%zu, 0) = %p [real, zero-size]", alignment, p);
        return p;
    }

    /* For small alignments (<= 16), regular malloc works since we
       always align to MALLOC_ALIGNMENT. For larger alignments (including
       page alignment for valloc), we need the full memalign path. */
    if (alignment <= MALLOC_ALIGNMENT) {
        TRACE("memalign(%zu, %zu) -> malloc (small alignment)", alignment, size);
        return malloc(size);
    }

    g_in_mguard = 1;

    size_t page_size = g_config.page_size;
    /* Need extra space for alignment */
    size_t padded;
    size_t effective;
    size_t aligned;
    size_t total;
    if (__builtin_add_overflow(size, alignment, &padded) ||
        checked_align_up(padded, MALLOC_ALIGNMENT, &effective) != 0 ||
        checked_align_up(effective, page_size, &aligned)) {
        TRACE("memalign(%zu, %zu): size overflow", alignment, size);
        g_in_mguard = 0;
        errno = ENOMEM;
        return NULL;
    }
    if (g_config.protect_below) {
        if (__builtin_add_overflow(page_size, aligned, &total)) {
            TRACE("memalign(%zu, %zu): size overflow", alignment, size);
            g_in_mguard = 0;
            errno = ENOMEM;
            return NULL;
        }
    } else if (__builtin_add_overflow(aligned, page_size, &total)) {
        TRACE("memalign(%zu, %zu): size overflow", alignment, size);
        g_in_mguard = 0;
        errno = ENOMEM;
        return NULL;
    }

    void *base = real_mmap(NULL, total, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        int saved_errno = errno;
        TRACE("memalign(%zu, %zu): mmap failed, errno=%d (%s)", alignment, size, saved_errno, strerror(saved_errno));
        g_in_mguard = 0;
        errno = ENOMEM;
        return NULL;
    }

    /* Find aligned address within region */
    uintptr_t align_base = (uintptr_t)base;
    if (g_config.protect_below) {
        align_base += page_size;
    }
    uintptr_t user_addr = ALIGN_UP(align_base, alignment);
    void *user_ptr = (void *)user_addr;

    void *guard_page = g_config.protect_below ? (char *)user_ptr - page_size
                                              : (char *)base + aligned;
    if (guard_install(guard_page, page_size) != 0) {
        TRACE("memalign(%zu, %zu): guard_install failed, falling back", alignment, size);
        real_munmap(base, total);
        g_in_mguard = 0;
        return real_memalign(alignment, size);
    }

    /* Calculate and fill pre-padding (before user pointer) */
    char *usable_base = g_config.protect_below ? (char *)guard_page + page_size : (char *)base;
    char *usable_end = g_config.protect_below ? (char *)base + total : (char *)guard_page;
    size_t pre_padding = (char *)user_ptr - usable_base;
    if (pre_padding > 0) {
        memset(usable_base, g_config.fill_pattern, pre_padding);
    }

    /* Calculate and fill post-padding (after user data, before guard page) */
    size_t post_padding = usable_end - ((char *)user_ptr + size);
    if (post_padding > 0) {
        memset((char *)user_ptr + size, g_config.fill_pattern, post_padding);
    }

    register_alloc(user_ptr, base, size, total, pre_padding, post_padding,
                   ALLOC_MEMALIGN, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    TRACE("memalign(%zu, %zu) = %p [guarded, base=%p, total=%zu]", alignment, size, user_ptr, base, total);

    g_in_mguard = 0;
    return user_ptr;
}

int posix_memalign(void **memptr, size_t alignment, size_t size) {
    /* Fast path */
    if (real_posix_memalign && (g_in_mguard || !mguard_is_initialized() || !g_config.enabled)) {
        int r = real_posix_memalign(memptr, alignment, size);
        TRACE("posix_memalign(%zu, %zu) = %d [real]", alignment, size, r);
        return r;
    }

    /*
     * POSIX requires EINVAL for null memptr, but glibc marks it nonnull.
     * Disable the warning for this required check.
     */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnonnull-compare"
    if (!memptr) return EINVAL;
#pragma GCC diagnostic pop
    if (alignment < sizeof(void *) || (alignment & (alignment - 1)) != 0) {
        TRACE("posix_memalign: invalid alignment %zu", alignment);
        return EINVAL;
    }

    void *ptr = memalign(alignment, size);
    if (!ptr && size != 0) {
        TRACE("posix_memalign(%zu, %zu): ENOMEM", alignment, size);
        return ENOMEM;
    }

    *memptr = ptr;
    TRACE("posix_memalign(%zu, %zu) = %p", alignment, size, ptr);
    return 0;
}

void *aligned_alloc(size_t alignment, size_t size) {
    /* Fast path */
    if (real_aligned_alloc && (g_in_mguard || !mguard_is_initialized() || !g_config.enabled)) {
        void *p = real_aligned_alloc(alignment, size);
        TRACE("aligned_alloc(%zu, %zu) = %p [real]", alignment, size, p);
        return p;
    }

    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        TRACE("aligned_alloc(%zu, %zu): invalid alignment", alignment, size);
        errno = EINVAL;
        return NULL;
    }

    /* aligned_alloc requires size to be multiple of alignment */
    if (size % alignment != 0) {
        TRACE("aligned_alloc(%zu, %zu): size not multiple of alignment", alignment, size);
        errno = EINVAL;
        return NULL;
    }
    void *ptr = memalign(alignment, size);
    TRACE("aligned_alloc(%zu, %zu) = %p", alignment, size, ptr);
    return ptr;
}

void *valloc(size_t size) {
    /* Fast path */
    if (real_valloc && (g_in_mguard || !mguard_is_initialized() || !g_config.enabled)) {
        void *p = real_valloc(size);
        TRACE("valloc(%zu) = %p [real]", size, p);
        return p;
    }

    TRACE("valloc(%zu) -> memalign(%zu, %zu)", size, g_config.page_size, size);
    return memalign(g_config.page_size, size);
}

/* ========== MMAP FAMILY ========== */

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    /* Must have real_mmap to do anything */
    if (!real_mmap) {
        errno = ENOSYS;
        return MAP_FAILED;
    }

    /* Skip if: MAP_FIXED, zero length, or explicit addr requested */
    if ((flags & MAP_FIXED) || length == 0 || addr != NULL) {
        void *p = real_mmap(addr, length, prot, flags, fd, offset);
        TRACE("mmap(%p, %zu, 0x%x, 0x%x, %d, %ld) = %p [real, fixed/addr/zero]",
              addr, length, prot, flags, fd, (long)offset, p);
        return p;
    }

    /* Fast path */
    if (g_in_mguard || !mguard_is_initialized() || !g_config.enabled) {
        void *p = real_mmap(addr, length, prot, flags, fd, offset);
        TRACE("mmap(%p, %zu, 0x%x, 0x%x, %d, %ld) = %p [real, fast path]",
              addr, length, prot, flags, fd, (long)offset, p);
        return p;
    }

    /* Skip small allocations if configured */
    if (length < g_config.min_size) {
        void *p = real_mmap(addr, length, prot, flags, fd, offset);
        TRACE("mmap(%p, %zu, 0x%x, 0x%x, %d, %ld) = %p [real, below min_size]",
              addr, length, prot, flags, fd, (long)offset, p);
        return p;
    }

    g_in_mguard = 1;

    size_t page_size = g_config.page_size;
    size_t aligned;
    size_t total;
    if (checked_align_up(length, page_size, &aligned) != 0 ||
        __builtin_add_overflow(aligned, page_size, &total)) {
        TRACE("mmap(%p, %zu, 0x%x, 0x%x, %d, %ld): size overflow",
              addr, length, prot, flags, fd, (long)offset);
        g_in_mguard = 0;
        errno = ENOMEM;
        return MAP_FAILED;
    }

    void *base;
    void *user_ptr;
    alloc_type_t type;
    size_t pre_padding = 0;
    size_t post_padding = 0;
    void *guard_page = NULL;

    if (fd >= 0 && !(flags & MAP_ANONYMOUS)) {
        /* File-backed mapping: reserve space first, then map file with MAP_FIXED */

        /* 1. Reserve contiguous anonymous space for file + guard page */
        base = real_mmap(NULL, total, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) {
            int saved_errno = errno;
            TRACE("mmap: file reservation failed, errno=%d (%s)", saved_errno, strerror(saved_errno));
            g_in_mguard = 0;
            return MAP_FAILED;
        }

        void *file_base = g_config.protect_below ? (char *)base + page_size : base;

        /* 2. Map the file over the reserved space using MAP_FIXED (safe - we own the reservation) */
        void *file_map = real_mmap(file_base, aligned, prot, flags | MAP_FIXED, fd, offset);
        if (file_map == MAP_FAILED) {
            int saved_errno = errno;
            TRACE("mmap: file MAP_FIXED failed, errno=%d (%s)", saved_errno, strerror(saved_errno));
            real_munmap(base, total);
            g_in_mguard = 0;
            return MAP_FAILED;
        }

        /* Verify MAP_FIXED returned the expected address */
        if (file_map != file_base) {
            TRACE("mmap: MAP_FIXED returned wrong address! expected=%p got=%p", file_base, file_map);
            real_munmap(file_map, aligned);
            real_munmap(base, total);
            g_in_mguard = 0;
            return real_mmap(addr, length, prot, flags, fd, offset); /* Fall back */
        }

        TRACE("mmap(file): base=%p, aligned=%zu, prot=0x%x, guard_at=%p",
              base, aligned, prot, g_config.protect_below ? base : (char*)base + aligned);

        /* Page-aligned for file mappings (no byte-level detection) */
        user_ptr = file_base;
        guard_page = g_config.protect_below ? base : (char *)base + aligned;
        type = ALLOC_MMAP_FILE;
        /* No padding for file mappings */
    } else {
        /* Anonymous mapping */
        base = real_mmap(NULL, total, prot, flags, fd, offset);
        if (base == MAP_FAILED) {
            int saved_errno = errno;
            TRACE("mmap: anonymous mmap failed, errno=%d (%s)", saved_errno, strerror(saved_errno));
            g_in_mguard = 0;
            return MAP_FAILED;
        }

        if (g_config.protect_below) {
            user_ptr = (char *)base + page_size;
            guard_page = base;
            /* Post-padding is between user data end and end of writable span */
            if (prot & PROT_WRITE) {
                post_padding = aligned - length;
            }
            if (post_padding > 0) {
                memset((char *)user_ptr + length, g_config.fill_pattern, post_padding);
            }
        } else {
            user_ptr = base;
            if (prot & PROT_WRITE) {
                post_padding = aligned - length;
                if (post_padding > 0) {
                    memset((char *)user_ptr + length, g_config.fill_pattern, post_padding);
                }
            }
            guard_page = (char *)base + aligned;
        }
        type = ALLOC_MMAP_ANON;
    }

    /* Install guard page */
    if (guard_install(guard_page, page_size) != 0) {
        TRACE("mmap: guard_install failed, falling back");
        real_munmap(base, total);
        g_in_mguard = 0;
        return real_mmap(addr, length, prot, flags, fd, offset);
    }

    register_alloc(user_ptr, base, length, total, pre_padding, post_padding,
                   type, prot, flags, fd, offset);

    TRACE("mmap(%p, %zu, 0x%x, 0x%x, %d, %ld) = %p [guarded, base=%p, total=%zu]",
          addr, length, prot, flags, fd, (long)offset, user_ptr, base, total);

    g_in_mguard = 0;
    return user_ptr;
}

int munmap(void *addr, size_t length) {
    if (!real_munmap) {
        errno = ENOSYS;
        return -1;
    }

    /* Fast path */
    if (g_in_mguard || !mguard_is_initialized() || !g_config.enabled) {
        int r = real_munmap(addr, length);
        TRACE("munmap(%p, %zu) = %d [real, fast path]", addr, length, r);
        return r;
    }

    g_in_mguard = 1;

    alloc_entry_t *entry = NULL;
    registry_claim_result_t claim = registry_claim_free(addr, &entry);
    if (claim == REGISTRY_CLAIM_NOT_FOUND) {
        registry_signal_read_begin();
        alloc_entry_t *containing = registry_lookup_containing_signal(addr);
        if (containing) {
            registry_signal_read_end();
            g_in_mguard = 0;
            errno = EINVAL;
            TRACE("munmap(%p, %zu) = -1 [partial tracked mapping unsupported]",
                  addr, length);
            return -1;
        }
        registry_signal_read_end();
        g_in_mguard = 0;
        int r = real_munmap(addr, length);
        TRACE("munmap(%p, %zu) = %d [real, not in registry]", addr, length, r);
        return r;
    }

    if (claim == REGISTRY_CLAIM_ALREADY_FREED) {
        report_double_munmap(addr, entry);
        registry_signal_read_end();
        /* report_double_munmap calls abort() */
    }

    TRACE("munmap(%p, %zu) [guarded, base=%p, real_size=%zu, magic=0x%x]",
          addr, length, entry->real_addr, entry->real_size, MAGIC_FREED);

    size_t unmap_len;
    if (checked_align_up(length, g_config.page_size, &unmap_len) != 0 ||
        unmap_len == 0) {
        registry_unclaim_free(entry);
        g_in_mguard = 0;
        errno = EINVAL;
        TRACE("munmap(%p, %zu) = -1 [invalid tracked length]", addr, length);
        return -1;
    }

    size_t user_span = mapped_user_span(entry);
    if (!is_mmap_entry(entry) && !tracked_length_matches(entry, length)) {
        registry_unclaim_free(entry);
        g_in_mguard = 0;
        errno = EINVAL;
        TRACE("munmap(%p, %zu) = -1 [partial non-mmap tracked allocation]",
              addr, length);
        return -1;
    }

    if (is_mmap_entry(entry) && !tracked_length_matches(entry, length) &&
        unmap_len < user_span) {
        size_t release_len = munmap_prefix_release_size(entry, unmap_len);
        void *old_user_addr = entry->user_addr;
        void *old_real_addr = entry->real_addr;
        size_t old_real_size = entry->real_size;
        size_t old_user_size = entry->user_size;
        size_t old_guard_size = entry->guard_size;

        int result = real_munmap(old_real_addr, release_len);
        if (result != 0) {
            int saved_errno = errno;
            registry_unclaim_free(entry);
            g_in_mguard = 0;
            errno = saved_errno;
            TRACE("munmap(%p, %zu) = %d [tracked prefix real_munmap failed]",
                  addr, length, result);
            return result;
        }

        registry_remove(old_user_addr);
        entry->user_addr = (char *)old_user_addr + unmap_len;
        entry->real_addr = (char *)old_real_addr + release_len;
        entry->user_size = old_user_size - unmap_len;
        entry->real_size = old_real_size - release_len;
        if (g_config.protect_below) {
            entry->guard_size = 0;
        } else {
            entry->guard_size = old_guard_size;
        }
        if (entry->fd >= 0 && !(entry->flags & MAP_ANONYMOUS)) {
            entry->offset += (off_t)unmap_len;
        }
        atomic_store_explicit(&entry->magic, MAGIC_ALIVE, memory_order_release);
        registry_insert(entry);

        TRACE("munmap(%p, %zu) = 0 [guarded prefix, remainder=%p/%zu]",
              addr, length, entry->user_addr, entry->user_size);

        g_in_mguard = 0;
        return 0;
    }

    /* Verify padding for anonymous mappings */
    if (entry->type == ALLOC_MMAP_ANON && !verify_padding(entry)) {
        report_overflow_on_free(addr, entry);
        /* report_overflow_on_free calls abort() */
    }
    registry_remove(addr);

    int result = real_munmap(entry->real_addr, entry->real_size);

    registry_free_entry(entry);

    TRACE("munmap(%p, %zu) = %d [guarded]", addr, length, result);

    g_in_mguard = 0;
    return result;
}

void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ...) {
    if (!real_mremap) {
        errno = ENOSYS;
        return MAP_FAILED;
    }

    /* Handle optional new_address argument for MREMAP_FIXED */
    void *new_address = NULL;
    if (flags & MREMAP_FIXED) {
        va_list ap;
        va_start(ap, flags);
        new_address = va_arg(ap, void *);
        va_end(ap);
    }

    /* Fast path - we don't handle mremap with guards, just pass through */
    if (g_in_mguard || !mguard_is_initialized() || !g_config.enabled) {
        void *p;
        if (flags & MREMAP_FIXED) {
            p = real_mremap(old_address, old_size, new_size, flags, new_address);
        } else {
            p = real_mremap(old_address, old_size, new_size, flags);
        }
        TRACE("mremap(%p, %zu, %zu, 0x%x) = %p [real, fast path]",
              old_address, old_size, new_size, flags, p);
        return p;
    }

    g_in_mguard = 1;

    alloc_entry_t *entry = NULL;
    registry_claim_result_t claim = registry_claim_realloc(old_address, &entry);
    if (claim == REGISTRY_CLAIM_NOT_FOUND) {
        registry_signal_read_begin();
        alloc_entry_t *containing = registry_lookup_containing_signal(old_address);
        if (containing) {
            registry_signal_read_end();
            g_in_mguard = 0;
            errno = EINVAL;
            TRACE("mremap(%p, %zu, %zu, 0x%x) = -1 [partial tracked mapping unsupported]",
                  old_address, old_size, new_size, flags);
            return MAP_FAILED;
        }
        registry_signal_read_end();
        g_in_mguard = 0;
        void *p;
        if (flags & MREMAP_FIXED) {
            p = real_mremap(old_address, old_size, new_size, flags, new_address);
        } else {
            p = real_mremap(old_address, old_size, new_size, flags);
        }
        TRACE("mremap(%p, %zu, %zu, 0x%x) = %p [real, not in registry]",
              old_address, old_size, new_size, flags, p);
        return p;
    }

    if (claim == REGISTRY_CLAIM_ALREADY_FREED) {
        report_mremap_freed(old_address, entry);
        registry_signal_read_end();
        /* report_mremap_freed calls abort() */
    }

    TRACE("mremap(%p, %zu, %zu, 0x%x) [guarded, doing alloc-copy-free]",
          old_address, old_size, new_size, flags);

    if (!(flags & MREMAP_MAYMOVE)) {
        registry_unclaim_realloc(entry);
        g_in_mguard = 0;
        errno = ENOMEM;
        TRACE("mremap: tracked in-place resize unsupported without MREMAP_MAYMOVE");
        return MAP_FAILED;
    }

    if (flags & MREMAP_FIXED) {
        registry_unclaim_realloc(entry);
        g_in_mguard = 0;
        errno = ENOMEM;
        TRACE("mremap: tracked MREMAP_FIXED unsupported");
        return MAP_FAILED;
    }

    if (flags != MREMAP_MAYMOVE) {
        registry_unclaim_realloc(entry);
        g_in_mguard = 0;
        errno = EOPNOTSUPP;
        TRACE("mremap: tracked flags other than MREMAP_MAYMOVE unsupported");
        return MAP_FAILED;
    }

    if (!tracked_length_matches(entry, old_size)) {
        registry_unclaim_realloc(entry);
        g_in_mguard = 0;
        errno = EINVAL;
        TRACE("mremap: tracked old_size mismatch unsupported");
        return MAP_FAILED;
    }

    if (new_size == old_size) {
        registry_unclaim_realloc(entry);
        g_in_mguard = 0;
        TRACE("mremap(%p, %zu, %zu, 0x%x) = %p [guarded no-op]",
              old_address, old_size, new_size, flags, old_address);
        return old_address;
    }

    int file_backed = entry->fd >= 0 && !(entry->flags & MAP_ANONYMOUS);
    if (!file_backed &&
        (entry->prot & (PROT_READ | PROT_WRITE)) != (PROT_READ | PROT_WRITE)) {
        registry_unclaim_realloc(entry);
        g_in_mguard = 0;
        errno = EOPNOTSUPP;
        TRACE("mremap: tracked non-readable/writable anonymous mapping unsupported");
        return MAP_FAILED;
    }

    /* For tracked allocations, do alloc-copy-free instead of real mremap */
    size_t copy_size = old_size == mapped_user_span(entry) ? old_size : entry->user_size;
    g_in_mguard = 0;

    void *new_ptr = mmap(NULL, new_size, entry->prot, entry->flags, entry->fd, entry->offset);
    if (new_ptr == MAP_FAILED) {
        registry_unclaim_realloc(entry);
        TRACE("mremap: mmap failed for new allocation");
        return MAP_FAILED;
    }

    if (!file_backed ||
        ((entry->flags & MAP_PRIVATE) &&
         (entry->prot & (PROT_READ | PROT_WRITE)) == (PROT_READ | PROT_WRITE))) {
        memcpy(new_ptr, old_address, MIN(copy_size, new_size));
    }

    g_in_mguard = 1;
    if (release_claimed_mmap_entry(old_address, entry) != 0) {
        int saved_errno = errno;
        g_in_mguard = 0;
        munmap(new_ptr, new_size);
        errno = saved_errno;
        return MAP_FAILED;
    }
    g_in_mguard = 0;

    TRACE("mremap(%p, %zu, %zu, 0x%x) = %p [guarded]",
          old_address, old_size, new_size, flags, new_ptr);

    return new_ptr;
}

/* ========== SIGACTION INTERPOSITION FOR JVM COMPATIBILITY ========== */

/*
 * In JVM mode (MGUARD_JVM=1), mguard does NOT install signal handlers.
 * This allows the JVM to handle SIGSEGV directly. When mguard's guard page
 * is hit, the JVM won't recognize the address, finds SIG_DFL in its chain,
 * and calls VMError::report_and_die() to generate hs_err.
 *
 * The sigaction interposition is no longer needed - we simply don't install
 * our handler in JVM mode (handled in mguard_init).
 */

/* Check if we're running in JVM mode */
int mguard_has_jvm_wrapper(void) {
    return g_mguard_jvm_mode;
}
