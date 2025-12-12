/*
 * Test: Realloc of freed pointer detection
 * This test attempts to realloc a freed pointer.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    printf("Testing realloc of freed pointer detection...\n");

    /* Allocate */
    char *buf = malloc(100);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }
    memset(buf, 'A', 100);

    char *saved_ptr = buf;

    printf("Buffer at %p, size 100 bytes\n", (void*)buf);
    printf("Freeing buffer...\n");

    /* Free it */
    free(buf);

    /* Dummy allocation to prevent same address reuse */
    void *dummy = malloc(4096);
    (void)dummy;

    printf("Attempting realloc of freed pointer...\n");

    /* Try to realloc freed pointer - should be detected */
    char *new_buf = realloc(saved_ptr, 200);

    /* Should not reach here if detection works */
    if (new_buf) {
        printf("ERROR: Realloc of freed pointer returned %p\n", (void*)new_buf);
        free(new_buf);
    } else {
        printf("realloc returned NULL (may or may not indicate detection)\n");
    }

    free(dummy);
    return 1;  /* Test should crash before here */
}
