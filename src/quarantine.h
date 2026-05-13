#ifndef MGUARD_QUARANTINE_H
#define MGUARD_QUARANTINE_H

#include "registry.h"

/*
 * Initialize the quarantine ring buffer.
 * Uses g_config.quarantine_entries for capacity.
 */
void quarantine_init(void);

/*
 * Add a freed allocation to quarantine.
 * The caller must already have marked the region as guard (SIGSEGV on access)
 * and published MAGIC_FREED.
 * If quarantine is full, oldest entries are evicted.
 */
void quarantine_add(alloc_entry_t *entry);

#endif /* MGUARD_QUARANTINE_H */
