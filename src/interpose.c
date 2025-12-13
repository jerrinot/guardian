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

/* Real function pointers */
real_malloc_t real_malloc = NULL;
real_free_t real_free = NULL;
real_calloc_t real_calloc = NULL;
real_realloc_t real_realloc = NULL;
real_memalign_t real_memalign = NULL;
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
static size_t bootstrap_pos = 0;

static void *bootstrap_alloc(size_t size) {
    size_t aligned = ALIGN_UP(size, MALLOC_ALIGNMENT);
    if (bootstrap_pos + aligned > sizeof(bootstrap_buf)) {
        fprintf(stderr, "[mguard] bootstrap_alloc(%zu): FAILED (buffer full)\n", size);
        return NULL;
    }
    void *p = bootstrap_buf + bootstrap_pos;
    bootstrap_pos += aligned;
    memset(p, 0, aligned);
    fprintf(stderr, "[mguard] bootstrap_alloc(%zu) = %p (pos=%zu)\n", size, p, bootstrap_pos);
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
    entry->pre_padding = pre_padding;
    entry->post_padding = post_padding;
    entry->type = type;
    entry->prot = prot;
    entry->flags = flags;
    entry->fd = fd;
    entry->offset = offset;
    entry->magic = MAGIC_ALIVE;

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
    if (g_in_mguard || !g_mguard_initialized || !g_config.enabled) {
        void *p = real_malloc(size);
        TRACE("malloc(%zu) = %p [real, in_mguard=%d init=%d enabled=%d]",
              size, p, g_in_mguard, g_mguard_initialized, g_config.enabled);
        return p;
    }

    /* Skip small allocations if configured */
    if (size < g_config.min_size) {
        void *p = real_malloc(size);
        TRACE("malloc(%zu) = %p [real, below min_size=%zu]", size, p, g_config.min_size);
        return p;
    }

    if (size == 0) return NULL;

    g_in_mguard = 1;

    size_t page_size = g_config.page_size;
    /* Align to MALLOC_ALIGNMENT to meet ABI requirements */
    size_t effective = ALIGN_UP(size, MALLOC_ALIGNMENT);
    size_t aligned = ALIGN_UP(effective, page_size);
    size_t total = aligned + page_size; /* +1 guard page */

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
        post_padding = aligned - effective;
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
    if (!real_free || g_in_mguard || !g_mguard_initialized || !g_config.enabled) {
        TRACE("free(%p) [real, in_mguard=%d init=%d enabled=%d]",
              ptr, g_in_mguard, g_mguard_initialized, g_config.enabled);
        if (real_free) real_free(ptr);
        return;
    }

    g_in_mguard = 1;

    TRACE("free(%p): looking up in registry...", ptr);
    alloc_entry_t *entry = registry_lookup(ptr);
    if (!entry) {
        /* Not our allocation - check if it's inside one of ours (bug detection) */
        alloc_entry_t *containing = registry_lookup_containing(ptr);
        if (containing) {
            TRACE("free(%p) BUG: not exact match but inside [%p + %zu], calling real_free anyway",
                  ptr, containing->user_addr, containing->user_size);
        } else {
            TRACE("free(%p) NOT FOUND in registry, calling real_free", ptr);
        }
        g_in_mguard = 0;
        real_free(ptr);
        return;
    }

    TRACE("free(%p) [guarded, base=%p, size=%zu, magic=0x%x]",
          ptr, entry->real_addr, entry->user_size, entry->magic);

    /* Check for double-free */
    if (entry->magic == MAGIC_FREED) {
        report_double_free(ptr, entry);
        /* report_double_free calls abort() */
    }

    /* Verify padding (detect overflow on free) */
    if (!verify_padding(entry)) {
        report_overflow_on_free(ptr, entry);
        /* report_overflow_on_free calls abort() */
    }

    entry->magic = MAGIC_FREED;

    /* Add to quarantine or release immediately */
    if (g_config.quarantine_entries > 0) {
        /*
         * Keep entry in registry for double-free detection.
         * The entry stays with MAGIC_FREED so subsequent free()
         * calls can detect the double-free.
         */
        TRACE("free(%p) -> quarantine", ptr);
        quarantine_add(entry);
    } else {
        /* No quarantine - remove and release immediately */
        TRACE("free(%p) -> munmap immediately", ptr);
        registry_remove(ptr);
        real_munmap(entry->real_addr, entry->real_size);
        registry_free_entry(entry);
    }

    g_in_mguard = 0;
}

void *calloc(size_t nmemb, size_t size) {
    /* Bootstrap path */
    if (!real_calloc) {
        size_t total = nmemb * size;
        return bootstrap_alloc(total); /* bootstrap_alloc zeros memory */
    }

    /* Check for overflow */
    size_t total;
    if (__builtin_mul_overflow(nmemb, size, &total)) {
        TRACE("calloc(%zu, %zu): overflow", nmemb, size);
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
        TRACE("realloc(NULL, %zu) -> malloc", size);
        return malloc(size);
    }
    if (size == 0) {
        TRACE("realloc(%p, 0) -> free", ptr);
        free(ptr);
        return NULL;
    }

    /* Bootstrap pointers can't be reallocated properly */
    if (is_bootstrap_ptr(ptr)) {
        void *new_ptr = malloc(size);
        if (new_ptr) {
            /* Copy what we can - we don't know original size */
            memcpy(new_ptr, ptr, size);
        }
        TRACE("realloc(%p, %zu) = %p [bootstrap]", ptr, size, new_ptr);
        return new_ptr;
    }

    /* Fast path */
    if (!real_realloc || g_in_mguard || !g_mguard_initialized || !g_config.enabled) {
        void *p = real_realloc ? real_realloc(ptr, size) : NULL;
        TRACE("realloc(%p, %zu) = %p [real]", ptr, size, p);
        return p;
    }

    g_in_mguard = 1;

    alloc_entry_t *entry = registry_lookup(ptr);
    if (!entry) {
        g_in_mguard = 0;
        void *p = real_realloc(ptr, size);
        TRACE("realloc(%p, %zu) = %p [real, not in registry]", ptr, size, p);
        return p;
    }

    TRACE("realloc(%p, %zu) [guarded, old_size=%zu]", ptr, size, entry->user_size);

    if (entry->magic != MAGIC_ALIVE) {
        report_realloc_freed(ptr, entry);
        /* report_realloc_freed calls abort() */
    }

    g_in_mguard = 0;

    /* Allocate new, copy, free old */
    void *new_ptr = malloc(size);
    if (!new_ptr) return NULL;

    memcpy(new_ptr, ptr, MIN(entry->user_size, size));

    TRACE("realloc(%p, %zu) = %p [guarded, freeing old]", ptr, size, new_ptr);
    free(ptr);

    return new_ptr;
}

void *memalign(size_t alignment, size_t size) {
    if (size == 0) return NULL;

    /* Fast path */
    if (!real_memalign || g_in_mguard || !g_mguard_initialized || !g_config.enabled) {
        void *p = real_memalign ? real_memalign(alignment, size) : NULL;
        TRACE("memalign(%zu, %zu) = %p [real]", alignment, size, p);
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
    size_t padded = size + alignment;
    size_t effective = ALIGN_UP(padded, MALLOC_ALIGNMENT);
    size_t aligned = ALIGN_UP(effective, page_size);
    size_t total = aligned + page_size;

    void *base = real_mmap(NULL, total, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        int saved_errno = errno;
        TRACE("memalign(%zu, %zu): mmap failed, errno=%d (%s)", alignment, size, saved_errno, strerror(saved_errno));
        g_in_mguard = 0;
        errno = ENOMEM;
        return NULL;
    }

    /* Guard page at end */
    void *guard_page = (char *)base + aligned;
    if (guard_install(guard_page, page_size) != 0) {
        TRACE("memalign(%zu, %zu): guard_install failed, falling back", alignment, size);
        real_munmap(base, total);
        g_in_mguard = 0;
        return real_memalign(alignment, size);
    }

    /* Find aligned address within region */
    uintptr_t user_addr = ALIGN_UP((uintptr_t)base, alignment);
    void *user_ptr = (void *)user_addr;

    /* Calculate and fill pre-padding (before user pointer) */
    size_t pre_padding = (char *)user_ptr - (char *)base;
    if (pre_padding > 0) {
        memset(base, g_config.fill_pattern, pre_padding);
    }

    /* Calculate and fill post-padding (after user data, before guard page) */
    size_t post_padding = (char *)guard_page - ((char *)user_ptr + size);
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
    if (g_in_mguard || !g_mguard_initialized || !g_config.enabled) {
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
    size_t aligned = ALIGN_UP(length, page_size);
    size_t total = aligned + page_size;

    void *base;
    void *user_ptr;
    alloc_type_t type;
    size_t pre_padding = 0;
    size_t post_padding = 0;

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

        /* 2. Map the file over the reserved space using MAP_FIXED (safe - we own the reservation) */
        void *file_map = real_mmap(base, aligned, prot, flags | MAP_FIXED, fd, offset);
        if (file_map == MAP_FAILED) {
            int saved_errno = errno;
            TRACE("mmap: file MAP_FIXED failed, errno=%d (%s)", saved_errno, strerror(saved_errno));
            real_munmap(base, total);
            g_in_mguard = 0;
            return MAP_FAILED;
        }

        /* Verify MAP_FIXED returned the expected address */
        if (file_map != base) {
            TRACE("mmap: MAP_FIXED returned wrong address! expected=%p got=%p", base, file_map);
            real_munmap(file_map, aligned);
            real_munmap(base, total);
            g_in_mguard = 0;
            return real_mmap(addr, length, prot, flags, fd, offset); /* Fall back */
        }

        TRACE("mmap(file): base=%p, aligned=%zu, prot=0x%x, guard_at=%p",
              base, aligned, prot, (char*)base + aligned);

        /* Guard page is the remaining anonymous page at base + aligned */
        /* Page-aligned for file mappings (no byte-level detection) */
        user_ptr = base;
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
            /* Post-padding is between user data end and guard page */
            post_padding = aligned - page_size - length;
            if (post_padding > 0 && (prot & PROT_WRITE)) {
                memset((char *)user_ptr + length, g_config.fill_pattern, post_padding);
            }
        } else {
            /* Byte-level detection */
            size_t effective = ALIGN_UP(length, MALLOC_ALIGNMENT);
            pre_padding = aligned - effective;
            user_ptr = (char *)base + pre_padding;
            /* Fill pre-padding */
            if (pre_padding > 0 && (prot & PROT_WRITE)) {
                memset(base, g_config.fill_pattern, pre_padding);
            }
        }
        type = ALLOC_MMAP_ANON;
    }

    /* Guard page at end */
    void *guard_page = (char *)base + aligned;
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
    if (g_in_mguard || !g_mguard_initialized || !g_config.enabled) {
        int r = real_munmap(addr, length);
        TRACE("munmap(%p, %zu) = %d [real, fast path]", addr, length, r);
        return r;
    }

    g_in_mguard = 1;

    alloc_entry_t *entry = registry_lookup(addr);
    if (!entry) {
        g_in_mguard = 0;
        int r = real_munmap(addr, length);
        TRACE("munmap(%p, %zu) = %d [real, not in registry]", addr, length, r);
        return r;
    }

    TRACE("munmap(%p, %zu) [guarded, base=%p, real_size=%zu, magic=0x%x]",
          addr, length, entry->real_addr, entry->real_size, entry->magic);

    if (entry->magic == MAGIC_FREED) {
        report_double_munmap(addr, entry);
        /* report_double_munmap calls abort() */
    }

    /* Verify padding for anonymous mappings */
    if (entry->type == ALLOC_MMAP_ANON && !verify_padding(entry)) {
        report_overflow_on_free(addr, entry);
        /* report_overflow_on_free calls abort() */
    }

    entry->magic = MAGIC_FREED;
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
    if (g_in_mguard || !g_mguard_initialized || !g_config.enabled) {
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

    alloc_entry_t *entry = registry_lookup(old_address);
    if (!entry) {
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

    TRACE("mremap(%p, %zu, %zu, 0x%x) [guarded, doing alloc-copy-free]",
          old_address, old_size, new_size, flags);

    /* For tracked allocations, do alloc-copy-free instead of real mremap */
    g_in_mguard = 0;

    void *new_ptr = mmap(NULL, new_size, entry->prot, entry->flags, entry->fd, entry->offset);
    if (new_ptr == MAP_FAILED) {
        TRACE("mremap: mmap failed for new allocation");
        return MAP_FAILED;
    }

    /* Only copy data for anonymous mappings - file mappings already have the content */
    if (entry->fd < 0 || (entry->flags & MAP_ANONYMOUS)) {
        /* Anonymous mapping - need to copy data */
        if (entry->prot & PROT_WRITE) {
            memcpy(new_ptr, old_address, MIN(entry->user_size, new_size));
        } else {
            /* Read-only anonymous mapping - can't copy, just use new mapping */
            TRACE("mremap: read-only anonymous mapping, skipping copy");
        }
    }
    /* File-backed mappings: no copy needed, file content is already there */

    munmap(old_address, old_size);

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
    const char *env = getenv("MGUARD_JVM");
    return (env && env[0] == '1');
}
