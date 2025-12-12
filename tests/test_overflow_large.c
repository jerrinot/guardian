/*
 * Test: Overflow detection on large allocations
 * This test verifies guard pages work for multi-page allocations.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MB (1024UL * 1024)

int main(void) {
    printf("Testing overflow detection on large allocation (1MB)...\n");

    /* Allocate 1 MB */
    char *buf = malloc(1 * MB);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    /* Fill with valid data */
    memset(buf, 'A', 1 * MB);

    printf("Buffer at %p, size 1MB\n", (void*)buf);
    printf("Writing to buf[1MB] (one byte past end)...\n");

    /* Off-by-one write on large buffer */
    buf[1 * MB] = 'X';

    /* Should not reach here */
    printf("ERROR: Overflow was NOT detected!\n");
    free(buf);
    return 1;
}
