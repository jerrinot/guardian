#include "config.h"
#include "registry.h"
#include "quarantine.h"
#include "interpose.h"
#include "report.h"
#include <stdio.h>

/* Global initialization state */
int g_mguard_initialized = 0;

/* Thread-local recursion guard */
__thread int g_in_mguard = 0;

__attribute__((constructor(101)))
static void mguard_init(void) {
    if (g_mguard_initialized) return;

    /* Parse configuration first (uses getenv, no allocations) */
    config_init();

    fprintf(stderr, "[mguard] init: enabled=%d, verbose=%d, min_size=%zu\n",
            g_config.enabled, g_config.verbose, g_config.min_size);

    if (!g_config.enabled) {
        g_mguard_initialized = 1;
        return;
    }

    /* Resolve real functions via dlsym */
    interpose_init();

    /* Initialize registry (uses mmap directly, no malloc) */
    registry_init();

    /* Initialize quarantine */
    quarantine_init();

    /* Install signal handler */
    report_init();

    if (g_config.verbose) {
        fprintf(stderr, "[mguard] initialized (page_size=%zu, quarantine=%zu MB)\n",
                g_config.page_size,
                g_config.quarantine_bytes / (1024 * 1024));
    }

    g_mguard_initialized = 1;
}

__attribute__((destructor))
static void mguard_fini(void) {
    if (!g_mguard_initialized || !g_config.enabled) return;

    if (g_config.verbose) {
        fprintf(stderr, "[mguard] shutting down\n");
    }

    /* Drain quarantine to release memory */
    quarantine_drain();
}
