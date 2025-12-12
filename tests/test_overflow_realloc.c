/*
 * Test: Overflow detection after realloc
 * This test writes past a realloc'd buffer.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    printf("Testing overflow detection after realloc...\n");

    /* Initial allocation */
    char *buf = malloc(50);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }
    memset(buf, 'A', 50);

    /* Grow with realloc */
    buf = realloc(buf, 200);
    if (!buf) {
        fprintf(stderr, "realloc failed\n");
        return 1;
    }

    /* Verify original data preserved */
    for (int i = 0; i < 50; i++) {
        if (buf[i] != 'A') {
            fprintf(stderr, "realloc corrupted original data\n");
            free(buf);
            return 1;
        }
    }

    /* Fill new space */
    memset(buf + 50, 'B', 150);

    printf("Buffer at %p, size 200 bytes (after realloc from 50)\n", (void*)buf);
    printf("Writing to buf[200] (one byte past end)...\n");

    /* Off-by-one write after realloc - this should trigger detection */
    buf[200] = 'X';

    /* Should not reach here */
    printf("ERROR: Overflow was NOT detected!\n");
    free(buf);
    return 1;
}
