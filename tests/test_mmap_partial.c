/*
 * Test: prefix munmap of tracked mappings keeps the suffix registered, while
 * interior munmap is rejected without corrupting mguard's registry state.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define FAIL(msg) do { fprintf(stderr, "FAIL: %s\n", msg); return 1; } while (0)

static int expect_einval(int result) {
    return result == -1 && errno == EINVAL;
}

int main(void) {
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (page_size == 0) {
        page_size = 4096;
    }

    char *p = mmap(NULL, page_size * 4, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
    }
    memset(p, 'A', page_size * 4);

    errno = 0;
    if (!expect_einval(munmap(p, 0))) {
        FAIL("munmap(base, 0) did not fail with EINVAL");
    }
    if (p[0] != 'A' || p[page_size * 4 - 1] != 'A') {
        FAIL("mapping changed after zero-length munmap");
    }

    errno = 0;
    if (munmap(p, page_size * 2) != 0) {
        FAIL("prefix munmap at base failed");
    }
    char *suffix = p + page_size * 2;
    if (suffix[0] != 'A' || suffix[page_size * 2 - 1] != 'A') {
        FAIL("suffix changed after prefix munmap");
    }
    char *reused = mmap(suffix - page_size, page_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (reused != suffix - page_size) {
        FAIL("reuse of released prefix page failed");
    }
    reused[0] = 'R';
    suffix[0] = 'B';
    suffix[page_size * 2 - 1] = 'C';
    if (munmap(suffix, page_size * 2) != 0) {
        FAIL("suffix munmap failed after prefix munmap");
    }
    if (reused[0] != 'R') {
        FAIL("suffix munmap unmapped reused prefix page");
    }
    if (munmap(reused, page_size) != 0) {
        FAIL("reused prefix page munmap failed");
    }

    p = mmap(NULL, page_size * 4, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("second mmap failed");
    }
    memset(p, 'A', page_size * 4);

    errno = 0;
    if (!expect_einval(munmap(p + page_size, page_size))) {
        FAIL("interior munmap did not fail with EINVAL");
    }
    if (p[0] != 'A' || p[page_size] != 'A' || p[page_size * 4 - 1] != 'A') {
        FAIL("mapping changed after interior munmap");
    }

    if (munmap(p, page_size * 4) != 0) {
        FAIL("full munmap failed after rejected interior munmap");
    }

    return 0;
}
