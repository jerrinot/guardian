#ifndef MGUARD_CONFIG_INTERNAL_H
#define MGUARD_CONFIG_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    int enabled;              /* MGUARD_ENABLED (default: 1) */
    int protect_below;        /* MGUARD_PROTECT_BELOW (default: 0) */
    size_t quarantine_bytes;  /* MGUARD_QUARANTINE_MB * 1024 * 1024 */
    uint8_t fill_pattern;     /* MGUARD_FILL (default: 0xAA) */
    int verbose;              /* MGUARD_VERBOSE (default: 0) */
    size_t min_size;          /* MGUARD_MIN_SIZE (default: 0) */
    size_t page_size;         /* Cached from sysconf(_SC_PAGESIZE) */
    size_t registry_buckets;  /* MGUARD_BUCKETS (default: 65536) */
} mguard_config_t;

extern mguard_config_t g_config;

void config_init(void);

#endif /* MGUARD_CONFIG_INTERNAL_H */
