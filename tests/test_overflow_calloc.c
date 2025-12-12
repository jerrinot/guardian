/*
 * Test: Overflow detection on calloc allocation
 * This test writes past a calloc'd array.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    printf("Testing overflow detection on calloc...\n");

    /* Allocate array of 100 ints */
    int *arr = calloc(100, sizeof(int));
    if (!arr) {
        fprintf(stderr, "calloc failed\n");
        return 1;
    }

    /* Verify zeroed and use array */
    for (int i = 0; i < 100; i++) {
        if (arr[i] != 0) {
            fprintf(stderr, "calloc did not zero memory\n");
            free(arr);
            return 1;
        }
        arr[i] = i * i;
    }

    printf("Array at %p, 100 ints (%zu bytes)\n", (void*)arr, 100 * sizeof(int));
    printf("Writing to arr[100] (one element past end)...\n");

    /* Off-by-one element write - this should trigger detection */
    arr[100] = 12345;

    /* Should not reach here */
    printf("ERROR: Overflow was NOT detected!\n");
    free(arr);
    return 1;
}
