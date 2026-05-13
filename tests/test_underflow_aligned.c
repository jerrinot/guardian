/*
 * Test: aligned allocation underflow detection in MGUARD_PROTECT_BELOW mode.
 */
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    volatile char *buf = memalign(8192, 4096);
    if (!buf) {
        fprintf(stderr, "memalign failed\n");
        return 1;
    }

    if ((uintptr_t)buf % 8192 != 0) {
        fprintf(stderr, "memalign returned unaligned pointer\n");
        return 1;
    }

    memset((void *)buf, 'A', 4096);
    buf[-1] = 'X';

    fprintf(stderr, "underflow was not detected\n");
    free((void *)buf);
    return 2;
}
