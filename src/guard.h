#ifndef MGUARD_GUARD_H
#define MGUARD_GUARD_H

#include <stddef.h>

/*
 * Install guard protection on a memory region.
 * Any access to this region will trigger SIGSEGV.
 * Returns 0 on success, -1 on failure.
 */
int guard_install(void *addr, size_t size);

/*
 * Remove guard protection from a memory region.
 * Returns 0 on success, -1 on failure.
 */
int guard_remove(void *addr, size_t size);

#endif /* MGUARD_GUARD_H */
