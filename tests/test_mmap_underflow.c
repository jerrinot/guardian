/*
 * Test: mmap underflow detection
 * This should trigger SIGSEGV when mguard is active with MGUARD_PROTECT_BELOW=1.
 */
#include <sys/mman.h>
#include <stdio.h>

int main(void) {
    size_t size = 4096;
    volatile char *buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        fprintf(stderr, "mmap failed\n");
        return 1;
    }

    buf[0] = 'A';

    /*
     * One byte before the returned mapping should hit the leading guard page
     * in MGUARD_PROTECT_BELOW mode.
     */
    buf[-1] = 'X';

    munmap((void *)buf, size);
    return 0;
}
