/*
 * Test: concurrent double-free detection.
 *
 * Both worker threads race to free the same guarded allocation. Exactly one
 * free may claim the entry; the other must report a double-free instead of
 * enqueueing or releasing the same registry entry a second time.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pthread_barrier_t start_barrier;
static void *shared_ptr;

static void *free_worker(void *arg) {
    (void)arg;

    int rc = pthread_barrier_wait(&start_barrier);
    if (rc != 0 && rc != PTHREAD_BARRIER_SERIAL_THREAD) {
        fprintf(stderr, "pthread_barrier_wait failed\n");
        abort();
    }

    free(shared_ptr);
    return NULL;
}

int main(void) {
    shared_ptr = malloc(100);
    if (!shared_ptr) {
        return 1;
    }
    memset(shared_ptr, 'A', 100);

    if (pthread_barrier_init(&start_barrier, NULL, 3) != 0) {
        return 1;
    }

    pthread_t t1;
    pthread_t t2;
    if (pthread_create(&t1, NULL, free_worker, NULL) != 0 ||
        pthread_create(&t2, NULL, free_worker, NULL) != 0) {
        return 1;
    }

    int rc = pthread_barrier_wait(&start_barrier);
    if (rc != 0 && rc != PTHREAD_BARRIER_SERIAL_THREAD) {
        return 1;
    }

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    fprintf(stderr, "concurrent double-free was not detected\n");
    return 2;
}
