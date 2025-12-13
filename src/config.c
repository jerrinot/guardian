#include "config.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

mguard_config_t g_config;

static long parse_env_long(const char *name, long default_val) {
    const char *val = getenv(name);
    if (!val || val[0] == '\0') {
        return default_val;
    }
    char *endptr;
    long result = strtol(val, &endptr, 10);
    if (*endptr != '\0') {
        return default_val;
    }
    return result;
}

static unsigned long parse_env_ulong(const char *name, unsigned long default_val) {
    const char *val = getenv(name);
    if (!val || val[0] == '\0') {
        return default_val;
    }
    char *endptr;
    unsigned long result = strtoul(val, &endptr, 0); /* 0 base allows hex */
    if (*endptr != '\0') {
        return default_val;
    }
    return result;
}

void config_init(void) {
    g_config.page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (g_config.page_size == 0) {
        g_config.page_size = 4096; /* Fallback */
    }

    g_config.enabled = (int)parse_env_long("MGUARD_ENABLED", 1);
    g_config.protect_below = (int)parse_env_long("MGUARD_PROTECT_BELOW", 0);

    /* Quarantine uses virtual address space only (no physical RAM) thanks to MADV_GUARD */
    long quarantine = parse_env_long("MGUARD_QUARANTINE", 1048576);
    if (quarantine < 0) quarantine = 0;
    g_config.quarantine_entries = (size_t)quarantine;

    g_config.fill_pattern = (uint8_t)parse_env_ulong("MGUARD_FILL", 0xAA);
    g_config.verbose = (int)parse_env_long("MGUARD_VERBOSE", 0);

    long min_size = parse_env_long("MGUARD_MIN_SIZE", 0);
    if (min_size < 0) min_size = 0;
    g_config.min_size = (size_t)min_size;

    /* Registry buckets - must be power of 2 */
    long buckets = parse_env_long("MGUARD_BUCKETS", 65536);
    if (buckets < 1024) buckets = 1024;
    if (buckets > 1048576) buckets = 1048576;
    /* Round up to next power of 2 */
    buckets--;
    buckets |= buckets >> 1;
    buckets |= buckets >> 2;
    buckets |= buckets >> 4;
    buckets |= buckets >> 8;
    buckets |= buckets >> 16;
    buckets++;
    g_config.registry_buckets = (size_t)buckets;
}
