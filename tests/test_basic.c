/*
 * Test: Basic malloc/free operations (should pass)
 * Verifies that normal memory operations work correctly with mguard.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    /* Test malloc/free */
    char *buf1 = malloc(100);
    if (!buf1) {
        fprintf(stderr, "malloc(100) failed\n");
        return 1;
    }
    memset(buf1, 'A', 100);
    free(buf1);

    /* Test calloc */
    int *buf2 = calloc(10, sizeof(int));
    if (!buf2) {
        fprintf(stderr, "calloc failed\n");
        return 1;
    }
    for (int i = 0; i < 10; i++) {
        if (buf2[i] != 0) {
            fprintf(stderr, "calloc didn't zero memory\n");
            return 1;
        }
        buf2[i] = i;
    }
    free(buf2);

    /* Test realloc */
    char *buf3 = malloc(50);
    if (!buf3) {
        fprintf(stderr, "malloc(50) failed\n");
        return 1;
    }
    memset(buf3, 'B', 50);

    buf3 = realloc(buf3, 200);
    if (!buf3) {
        fprintf(stderr, "realloc failed\n");
        return 1;
    }
    /* Verify original data preserved */
    for (int i = 0; i < 50; i++) {
        if (buf3[i] != 'B') {
            fprintf(stderr, "realloc didn't preserve data\n");
            return 1;
        }
    }
    memset(buf3 + 50, 'C', 150);
    free(buf3);

    /* Test multiple allocations */
    void *ptrs[100];
    for (int i = 0; i < 100; i++) {
        ptrs[i] = malloc(100 + i * 10);
        if (!ptrs[i]) {
            fprintf(stderr, "allocation %d failed\n", i);
            return 1;
        }
    }
    for (int i = 0; i < 100; i++) {
        free(ptrs[i]);
    }

    printf("All basic tests passed!\n");
    return 0;
}
