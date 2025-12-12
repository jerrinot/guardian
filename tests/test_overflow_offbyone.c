/*
 * Test: Off-by-one overflow detection
 * This test writes exactly one byte past the allocation.
 * It should trigger MGUARD detection.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    printf("Testing off-by-one overflow detection...\n");

    /* Allocate 100 bytes */
    char *buf = malloc(100);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    /* Fill with valid data */
    memset(buf, 'A', 100);

    printf("Buffer at %p, size 100 bytes\n", (void*)buf);
    printf("Writing to buf[100] (one byte past end)...\n");

    /* Off-by-one write - this should trigger detection */
    buf[100] = 'X';

    /* Should not reach here */
    printf("ERROR: Off-by-one write was NOT detected!\n");
    free(buf);
    return 1;
}
