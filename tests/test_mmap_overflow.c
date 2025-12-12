/*
 * Test: mmap overflow detection
 * This should trigger SIGSEGV when mguard is active.
 */
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    size_t size = 1000;
    volatile char *buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) return 1;

    printf("mmap returned: %p\n", (void*)buf);
    memset((void*)buf, 'A', size);

    /*
     * Write well past the end to ensure we hit the guard page.
     * mmap allocations are also subject to alignment.
     *
     * Using volatile to prevent compiler from optimizing this away.
     */
    buf[4096] = 'X';
    printf("Write done (should not reach here)\n");

    munmap((void*)buf, size);
    return 0;
}
