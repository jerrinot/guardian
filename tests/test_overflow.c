/*
 * Test: Buffer overflow detection
 * This should trigger SIGSEGV when mguard is active.
 *
 * Note: Due to 16-byte alignment requirements, overflow detection
 * may not trigger for the last 0-15 bytes. We write well past the
 * allocation to ensure we hit the guard page.
 */
#include <stdlib.h>
#include <string.h>

int main(void) {
    volatile char *buf = malloc(100);
    if (!buf) return 1;

    /*
     * Write 4096+ bytes past the end to ensure we hit the guard page.
     * With 16-byte alignment, effective size is 112 bytes, but the
     * guard page is at the next page boundary (typically 4096 bytes
     * from the allocation base).
     *
     * Using volatile to prevent compiler from optimizing this away.
     */
    buf[4096] = 'X';

    free((void*)buf);
    return 0;
}
