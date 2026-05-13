#include "config.h"
#include "registry.h"
#include "quarantine.h"
#include "interpose.h"
#include "report.h"
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>

/* Global initialization state */
_Atomic int g_mguard_initialized = 0;
int g_mguard_jvm_mode = 0;

/* Thread-local recursion guard */
__thread int g_in_mguard = 0;

__attribute__((constructor(101)))
static void mguard_init(void) {
    if (mguard_is_initialized()) return;

    /* Parse configuration first (uses getenv, no allocations) */
    config_init();

    const char *jvm_mode = getenv("MGUARD_JVM");
    g_mguard_jvm_mode = (jvm_mode && jvm_mode[0] == '1');
    fprintf(stderr, "[mguard] init: enabled=%d, verbose=%d, min_size=%zu, jvm_mode=%d\n",
            g_config.enabled, g_config.verbose, g_config.min_size, g_mguard_jvm_mode);

    /* Resolve real functions via dlsym */
    interpose_init();

    if (!g_config.enabled) {
        atomic_store_explicit(&g_mguard_initialized, 1, memory_order_release);
        return;
    }

    /* Initialize registry (uses mmap directly, no malloc) */
    registry_init();

    /* Initialize quarantine */
    quarantine_init();

    /* Install signal handler (skip in JVM mode - let JVM handle signals) */
    if (!g_mguard_jvm_mode) {
        report_init();
    } else {
        fprintf(stderr, "[mguard] JVM mode: skipping signal handler installation\n");
    }

    if (g_config.verbose) {
        fprintf(stderr, "[mguard] initialized (page_size=%zu, quarantine=%zu entries)\n",
                g_config.page_size,
                g_config.quarantine_entries);
    }

    atomic_store_explicit(&g_mguard_initialized, 1, memory_order_release);
}
