/*
 * Test: Use-after-free detection
 * This should trigger SIGSEGV when mguard is active (with quarantine).
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    volatile char *buf = malloc(100);
    if (!buf) return 1;

    memset((void*)buf, 'A', 100);
    free((void*)buf);

    /*
     * Access freed memory - should trigger guard page (quarantine).
     * Using volatile and printf to prevent optimization.
     */
    volatile char c = buf[50];
    printf("Read: %c\n", c);

    return 0;
}
