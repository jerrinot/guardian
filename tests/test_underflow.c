/*
 * Test: Buffer underflow detection
 * This should trigger SIGSEGV when mguard is active with MGUARD_PROTECT_BELOW=1.
 *
 * Note: Run with: MGUARD_PROTECT_BELOW=1 LD_PRELOAD=./libmguard.so ./test_underflow
 */
#include <stdlib.h>

int main(void) {
    volatile char *buf = malloc(100);
    if (!buf) return 1;

    /*
     * Write well before the start to ensure we hit the guard page.
     * With MGUARD_PROTECT_BELOW=1, guard page is before the allocation.
     *
     * Using volatile to prevent compiler from optimizing this away.
     */
    buf[-4096] = 'X';

    free((void*)buf);
    return 0;
}
