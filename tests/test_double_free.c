/*
 * Test: Double-free detection
 * This should abort when mguard is active.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    volatile char *buf = malloc(100);
    if (!buf) return 1;

    memset((void*)buf, 'A', 100);

    /* Store pointer to prevent optimization */
    void *ptr = (void*)buf;
    printf("Allocated: %p\n", ptr);

    free(ptr);
    printf("First free done\n");

    /* Double free - mguard should detect this */
    free(ptr);
    printf("Second free done (should not reach here)\n");

    return 0;
}
