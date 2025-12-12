#ifndef MGUARD_REPORT_H
#define MGUARD_REPORT_H

#include "registry.h"

/*
 * Initialize error reporting and install SIGSEGV handler.
 */
void report_init(void);

/*
 * Report a double-free error and abort.
 */
void report_double_free(void *ptr, alloc_entry_t *entry);

/*
 * Report a double-munmap error and abort.
 */
void report_double_munmap(void *ptr, alloc_entry_t *entry);

/*
 * Report a buffer overflow detected on free and abort.
 */
void report_overflow_on_free(void *ptr, alloc_entry_t *entry);

/*
 * Report realloc of freed pointer and abort.
 */
void report_realloc_freed(void *ptr, alloc_entry_t *entry);

#endif /* MGUARD_REPORT_H */
