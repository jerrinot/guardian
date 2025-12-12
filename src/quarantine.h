#ifndef MGUARD_QUARANTINE_H
#define MGUARD_QUARANTINE_H

#include "registry.h"

/*
 * Initialize the quarantine ring buffer.
 * Uses g_config.quarantine_bytes for max size.
 */
void quarantine_init(void);

/*
 * Add a freed allocation to quarantine.
 * The entire region will be marked as guard (SIGSEGV on access).
 * If quarantine is full, oldest entries are evicted.
 */
void quarantine_add(alloc_entry_t *entry);

/*
 * Drain all entries from quarantine and release memory.
 * Called during library shutdown.
 */
void quarantine_drain(void);

#endif /* MGUARD_QUARANTINE_H */
