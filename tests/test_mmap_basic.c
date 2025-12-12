/*
 * Test: Basic mmap/munmap operations (should pass)
 * Verifies that normal mmap operations work correctly with mguard.
 */
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    /* Test anonymous mmap */
    size_t size1 = 4096 * 3;
    char *buf1 = mmap(NULL, size1, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf1 == MAP_FAILED) {
        fprintf(stderr, "mmap(anonymous) failed\n");
        return 1;
    }
    memset(buf1, 'A', size1);
    if (munmap(buf1, size1) != 0) {
        fprintf(stderr, "munmap failed\n");
        return 1;
    }

    /* Test multiple mmaps */
    void *ptrs[10];
    for (int i = 0; i < 10; i++) {
        ptrs[i] = mmap(NULL, 4096 * (i + 1), PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptrs[i] == MAP_FAILED) {
            fprintf(stderr, "mmap %d failed\n", i);
            return 1;
        }
        memset(ptrs[i], 'B' + i, 4096 * (i + 1));
    }
    for (int i = 0; i < 10; i++) {
        if (munmap(ptrs[i], 4096 * (i + 1)) != 0) {
            fprintf(stderr, "munmap %d failed\n", i);
            return 1;
        }
    }

    printf("All mmap basic tests passed!\n");
    return 0;
}
