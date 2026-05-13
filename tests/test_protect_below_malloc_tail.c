/*
 * Test: protect-below malloc checks the full tail padding.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    size_t size = 4081;
    volatile char *buf = malloc(size);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    memset((void *)buf, 'A', size);

    /*
     * This lands in the tail bytes that were previously left unfilled when
     * size was not 16-byte aligned.
     */
    buf[4095] = 'X';

    free((void *)buf);
    return 1;
}
