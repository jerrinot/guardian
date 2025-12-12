#include "guard.h"
#include <mguard/config.h>
#include <sys/mman.h>

int guard_install(void *addr, size_t size) {
    return madvise(addr, size, MADV_GUARD_INSTALL);
}

int guard_remove(void *addr, size_t size) {
    return madvise(addr, size, MADV_GUARD_REMOVE);
}
