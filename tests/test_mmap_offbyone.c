/*
 * Test: Off-by-one overflow detection on mmap
 * This test writes exactly one byte past an mmap'd region.
 */
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    printf("Testing off-by-one overflow detection on mmap...\n");

    /*
     * mmap a non-page and non-16-byte-aligned size. The byte just past this
     * length lands in mguard's intra-page post-padding, not the guard page.
     */
    size_t size = 4001;
    char *buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        fprintf(stderr, "mmap failed\n");
        return 1;
    }

    /* Fill with valid data */
    memset(buf, 'A', size);

    printf("Buffer at %p, size %zu bytes\n", (void*)buf, size);
    printf("Writing to buf[%zu] (one byte past end)...\n", size);

    /* Off-by-one write - this should be detected when munmap checks padding. */
    buf[size] = 'X';

    /* Should not reach here */
    printf("ERROR: Off-by-one write was NOT detected!\n");
    munmap(buf, size);
    return 1;
}
