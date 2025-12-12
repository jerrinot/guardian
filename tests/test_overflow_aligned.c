/*
 * Test: Overflow detection on aligned allocations
 * This test verifies guard pages work correctly with memalign.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    printf("Testing overflow detection on aligned allocation...\n");

    /* Allocate 64-byte aligned, 1000 bytes */
    void *ptr = NULL;
    if (posix_memalign(&ptr, 64, 1000) != 0 || !ptr) {
        fprintf(stderr, "posix_memalign failed\n");
        return 1;
    }

    char *buf = ptr;

    /* Fill with valid data */
    memset(buf, 'A', 1000);

    printf("Buffer at %p, size 1000 bytes, 64-byte aligned\n", (void*)buf);
    printf("Writing to buf[1000] (one byte past end)...\n");

    /* Off-by-one write - this should trigger detection */
    buf[1000] = 'X';

    /* Should not reach here */
    printf("ERROR: Overflow was NOT detected!\n");
    free(buf);
    return 1;
}
