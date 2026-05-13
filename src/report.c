#include "report.h"
#include "registry.h"
#include "interpose.h"
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* Saved handlers for chaining (e.g., JVM installs its own) */
static struct sigaction old_sigsegv_action;
static struct sigaction old_sigbus_action;

/* Prevent re-entry when chaining to JVM handler that chains back to us */
static __thread volatile sig_atomic_t in_sigsegv_handler
    __attribute__((tls_model("initial-exec"))) = 0;
static __thread volatile sig_atomic_t in_sigbus_handler
    __attribute__((tls_model("initial-exec"))) = 0;

/*
 * Terminate the process. In JVM mode, trigger SIGSEGV so the JVM
 * generates hs_err. Otherwise, call abort().
 */
static void mguard_die(void) {
    if (g_mguard_jvm_mode) {
        /* Trigger SIGSEGV so JVM generates hs_err */
        *(volatile int *)0 = 0;
    }
    abort();
}

/*
 * Chain to previous signal handler.
 * Used when fault is not in mguard-managed memory (e.g., JVM internal SIGSEGV).
 */
static void chain_handler(struct sigaction *old_action, int sig, siginfo_t *info, void *ucontext) {
    if (old_action->sa_flags & SA_SIGINFO) {
        if (old_action->sa_sigaction) {
            old_action->sa_sigaction(sig, info, ucontext);
            return;
        }
    } else {
        if (old_action->sa_handler == SIG_DFL) {
            signal(sig, SIG_DFL);
            raise(sig);
            return;
        } else if (old_action->sa_handler == SIG_IGN) {
            return;
        } else if (old_action->sa_handler) {
            old_action->sa_handler(sig);
            return;
        }
    }
    /* No handler - use default */
    signal(sig, SIG_DFL);
    raise(sig);
}

/*
 * Async-signal-safe write to stderr.
 * Uses write() syscall directly, not stdio.
 */
static void write_str(const char *s) {
    if (s) {
        /* In signal handler - nothing useful we can do if write fails */
        size_t len = 0;
        const volatile char *p = (const volatile char *)s;
        while (p[len] != '\0') {
            len++;
        }
        ssize_t ret __attribute__((unused)) = write(STDERR_FILENO, s, len);
    }
}

static void write_line(const char *s) {
    write_str(s);
    write_str("\n");
}

/*
 * Convert pointer to hex string (async-signal-safe).
 */
static void ptr_to_hex(void *ptr, char *buf, size_t buflen) {
    static const char hex[] = "0123456789abcdef";
    uintptr_t val = (uintptr_t)ptr;

    if (buflen < 19) { /* "0x" + 16 hex digits + null */
        buf[0] = '\0';
        return;
    }

    buf[0] = '0';
    buf[1] = 'x';

    for (int i = 15; i >= 0; i--) {
        buf[2 + (15 - i)] = hex[(val >> (i * 4)) & 0xf];
    }
    buf[18] = '\0';
}

/*
 * Convert size_t to decimal string (async-signal-safe).
 */
static void size_to_str(size_t val, char *buf, size_t buflen) {
    if (buflen == 0) return;

    if (val == 0) {
        buf[0] = '0';
        buf[1] = '\0';
        return;
    }

    char tmp[32];
    int i = 0;
    while (val > 0 && i < 31) {
        tmp[i++] = '0' + (val % 10);
        val /= 10;
    }

    int j = 0;
    while (i > 0 && (size_t)j < buflen - 1) {
        buf[j++] = tmp[--i];
    }
    buf[j] = '\0';
}

static const char *alloc_type_str(alloc_type_t type) {
    switch (type) {
        case ALLOC_MALLOC: return "malloc";
        case ALLOC_CALLOC: return "calloc";
        case ALLOC_REALLOC: return "realloc";
        case ALLOC_MEMALIGN: return "memalign";
        case ALLOC_MMAP_ANON: return "mmap(anon)";
        case ALLOC_MMAP_FILE: return "mmap(file)";
        default: return "unknown";
    }
}

static void print_separator(void) {
    write_line("================================================================================");
}

static void print_entry_info(alloc_entry_t *entry) {
    char buf[32];

    write_str("Allocation:      ");
    ptr_to_hex(entry->user_addr, buf, sizeof(buf));
    write_str(buf);
    write_str(" (");
    size_to_str(entry->user_size, buf, sizeof(buf));
    write_str(buf);
    write_str(" bytes, ");
    write_str(alloc_type_str(entry->type));
    write_line(")");

    write_str("Real base:       ");
    ptr_to_hex(entry->real_addr, buf, sizeof(buf));
    write_line(buf);

    write_str("Total size:      ");
    size_to_str(entry->real_size, buf, sizeof(buf));
    write_str(buf);
    write_line(" bytes");
}

/*
 * SIGSEGV handler - called when guard page is accessed.
 */
static void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    void *fault_addr = info->si_addr;
    char buf[32];

    /*
     * Prevent re-entry.
     *
     * The JVM saves mguard's handler in its signal chain. When a SIGSEGV
     * occurs, the JVM's handler runs first, then chains to us. If we've
     * already handled this signal (in_sigsegv_handler is set), just return
     * and let the JVM continue its processing.
     */
    if (in_sigsegv_handler) {
        return;
    }

    registry_signal_read_begin();

    /* Look up allocation containing this address */
    alloc_entry_t *entry = registry_lookup_containing_signal(fault_addr);

    /*
     * If fault is not in mguard-managed memory, chain to previous handler.
     * This is critical for JVM which uses SIGSEGV for null checks, safepoints, etc.
     */
    if (!entry) {
        registry_signal_read_end();
        chain_handler(&old_sigsegv_action, sig, info, ucontext);
        return;
    }

    uintptr_t user_start = (uintptr_t)entry->user_addr;
    uintptr_t user_end = user_start + entry->user_size;
    uintptr_t fault = (uintptr_t)fault_addr;
    uint32_t magic = atomic_load_explicit(&entry->magic, memory_order_acquire);

    /*
     * Fault within valid user buffer is not ours - chain to previous handler.
     * Could be JVM internal or other legitimate SIGSEGV usage.
     */
    if (fault >= user_start && fault < user_end &&
        magic != MAGIC_FREED && magic != MAGIC_FREEING) {
        registry_signal_read_end();
        chain_handler(&old_sigsegv_action, sig, info, ucontext);
        return;
    }

    /* This is our fault - report it */
    in_sigsegv_handler = 1;
    print_separator();

    if (magic == MAGIC_FREED || magic == MAGIC_FREEING) {
        write_line("MGUARD: Use-after-free detected!");
        print_separator();
        write_str("Fault address:   ");
        ptr_to_hex(fault_addr, buf, sizeof(buf));
        write_line(buf);
        print_entry_info(entry);
    } else if (fault >= user_end) {
        write_line("MGUARD: Buffer overflow detected!");
        print_separator();
        write_str("Fault address:   ");
        ptr_to_hex(fault_addr, buf, sizeof(buf));
        write_line(buf);
        print_entry_info(entry);
        write_str("Overflow:        ");
        size_to_str(fault - user_end + 1, buf, sizeof(buf));
        write_str(buf);
        write_line(" byte(s) past end");
    } else if (fault < user_start) {
        write_line("MGUARD: Buffer underflow detected!");
        print_separator();
        write_str("Fault address:   ");
        ptr_to_hex(fault_addr, buf, sizeof(buf));
        write_line(buf);
        print_entry_info(entry);
        write_str("Underflow:       ");
        size_to_str(user_start - fault, buf, sizeof(buf));
        write_str(buf);
        write_line(" byte(s) before start");
    }

    print_separator();
    registry_signal_read_end();

    /*
     * If running with JVM wrapper, just return - the wrapper will call JVM
     * which will generate hs_err and terminate.
     *
     * If running standalone (no JVM), terminate with core dump.
     */
    if (g_mguard_jvm_mode) {
        /* Let wrapper continue to JVM handler */
        return;
    }

    /* No JVM - terminate with default handler for core dump */
    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
}

/*
 * SIGBUS handler - called on bus error (e.g., file mapping beyond EOF).
 */
static void sigbus_handler(int sig, siginfo_t *info, void *ucontext) {
    void *fault_addr = info->si_addr;
    char buf[32];

    /* Prevent re-entry (JVM handler may chain back to us) */
    if (in_sigbus_handler) {
        /* Just return - let the caller (JVM) continue its crash handling */
        return;
    }

    registry_signal_read_begin();

    alloc_entry_t *entry = registry_lookup_containing_signal(fault_addr);

    /*
     * If fault is not in mguard-managed memory, chain to previous handler.
     */
    if (!entry) {
        registry_signal_read_end();
        chain_handler(&old_sigbus_action, sig, info, ucontext);
        return;
    }

    in_sigbus_handler = 1;
    print_separator();
    write_line("MGUARD: SIGBUS in tracked allocation (file mapping issue?)");
    print_separator();
    write_str("Fault address:   ");
    ptr_to_hex(fault_addr, buf, sizeof(buf));
    write_line(buf);
    print_entry_info(entry);
    write_str("Offset:          ");
    size_to_str((uintptr_t)fault_addr - (uintptr_t)entry->user_addr, buf, sizeof(buf));
    write_str(buf);
    write_line(" byte(s) from start");
    print_separator();
    registry_signal_read_end();

    /* Chain to next handler (same logic as SIGSEGV handler) */
    struct sigaction current;
    if (sigaction(SIGBUS, NULL, &current) == 0) {
        if (current.sa_flags & SA_SIGINFO) {
            if (current.sa_sigaction && current.sa_sigaction != sigbus_handler) {
                current.sa_sigaction(sig, info, ucontext);
            }
        } else if (current.sa_handler && current.sa_handler != SIG_DFL &&
                   current.sa_handler != SIG_IGN) {
            current.sa_handler(sig);
        }
    }

    signal(SIGBUS, SIG_DFL);
    raise(SIGBUS);
}

void report_init(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsegv_handler;
    /*
     * SA_SIGINFO: Use sa_sigaction instead of sa_handler.
     * Do not use SA_RESETHAND: a recoverable, non-mguard SIGSEGV would remove
     * this handler before future guard-page faults can be reported.
     */
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_sigsegv_action);

    /* Also handle SIGBUS for file mapping issues */
    sa.sa_sigaction = sigbus_handler;
    sigaction(SIGBUS, &sa, &old_sigbus_action);
}

void report_double_free(void *ptr, alloc_entry_t *entry) {
    char buf[32];

    print_separator();
    write_line("MGUARD: Double-free detected!");
    print_separator();

    write_str("Freed pointer:   ");
    ptr_to_hex(ptr, buf, sizeof(buf));
    write_line(buf);

    print_entry_info(entry);
    print_separator();

    mguard_die();
}

void report_double_munmap(void *ptr, alloc_entry_t *entry) {
    char buf[32];

    print_separator();
    write_line("MGUARD: Double-munmap detected!");
    print_separator();

    write_str("Unmapped addr:   ");
    ptr_to_hex(ptr, buf, sizeof(buf));
    write_line(buf);

    print_entry_info(entry);
    print_separator();

    mguard_die();
}

void report_overflow_on_free(void *ptr, alloc_entry_t *entry) {
    char buf[32];

    print_separator();
    write_line("MGUARD: Buffer overflow detected on free!");
    print_separator();

    write_str("Freed pointer:   ");
    ptr_to_hex(ptr, buf, sizeof(buf));
    write_line(buf);

    print_entry_info(entry);
    write_line("Padding pattern was corrupted (overflow occurred before free)");
    print_separator();

    mguard_die();
}

void report_realloc_freed(void *ptr, alloc_entry_t *entry) {
    char buf[32];

    print_separator();
    write_line("MGUARD: Realloc of freed pointer!");
    print_separator();

    write_str("Pointer:         ");
    ptr_to_hex(ptr, buf, sizeof(buf));
    write_line(buf);

    print_entry_info(entry);
    print_separator();

    mguard_die();
}

void report_mremap_freed(void *ptr, alloc_entry_t *entry) {
    char buf[32];

    print_separator();
    write_line("MGUARD: Mremap of freed mapping!");
    print_separator();

    write_str("Mapping:         ");
    ptr_to_hex(ptr, buf, sizeof(buf));
    write_line(buf);

    print_entry_info(entry);
    print_separator();

    mguard_die();
}
