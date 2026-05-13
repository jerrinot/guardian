/*
 * Preload helper for bootstrap calloc overflow testing.
 *
 * This library is preloaded after libmguard.so so the calloc symbol binds to
 * mguard, but the dynamic loader still runs this constructor before mguard's
 * constructor resolves real_calloc.
 */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void probe_bootstrap_calloc_overflow(void) {
    void *(*volatile calloc_fn)(size_t, size_t) = calloc;

    volatile size_t overflowing_nmemb = SIZE_MAX / 2 + 2;
    errno = 0;
    void *p = calloc_fn(overflowing_nmemb, 2);
    if (p != NULL) {
        const char msg[] = "FAIL: bootstrap calloc overflow returned non-NULL\n";
        ssize_t ret __attribute__((unused)) = write(STDERR_FILENO, msg, sizeof(msg) - 1);
        _exit(42);
    }
    if (errno != ENOMEM) {
        const char msg[] = "FAIL: bootstrap calloc overflow did not set ENOMEM\n";
        ssize_t ret __attribute__((unused)) = write(STDERR_FILENO, msg, sizeof(msg) - 1);
        _exit(43);
    }

    volatile size_t huge_nmemb = SIZE_MAX;
    errno = 0;
    p = calloc_fn(huge_nmemb, 1);
    if (p != NULL) {
        const char msg[] = "FAIL: bootstrap calloc huge size returned non-NULL\n";
        ssize_t ret __attribute__((unused)) = write(STDERR_FILENO, msg, sizeof(msg) - 1);
        _exit(44);
    }
    if (errno != ENOMEM) {
        const char msg[] = "FAIL: bootstrap calloc huge size did not set ENOMEM\n";
        ssize_t ret __attribute__((unused)) = write(STDERR_FILENO, msg, sizeof(msg) - 1);
        _exit(45);
    }
}
