#include "report.h"
#include "registry.h"
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/*
 * Async-signal-safe write to stderr.
 * Uses write() syscall directly, not stdio.
 */
static void write_str(const char *s) {
    if (s) {
        write(STDERR_FILENO, s, strlen(s));
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
    (void)sig;
    (void)ucontext;

    void *fault_addr = info->si_addr;
    char buf[32];

    /* Look up allocation containing this address */
    alloc_entry_t *entry = registry_lookup_containing(fault_addr);

    print_separator();

    if (entry) {
        uintptr_t user_start = (uintptr_t)entry->user_addr;
        uintptr_t user_end = user_start + entry->user_size;
        uintptr_t fault = (uintptr_t)fault_addr;

        if (entry->magic == MAGIC_FREED) {
            write_line("MGUARD: Use-after-free detected!");
            print_separator();
            write_str("Fault address:   ");
            ptr_to_hex(fault_addr, buf, sizeof(buf));
            write_line(buf);
            print_entry_info(entry);
        } else if (fault >= user_end) {
            /* Fault past end of user buffer - overflow */
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
            /* Fault before start of user buffer - underflow */
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
        } else {
            /* Fault within user buffer - not mguard's detection, pass through */
            write_line("MGUARD: SIGSEGV within valid allocation (not overflow)");
            print_separator();
            write_str("Fault address:   ");
            ptr_to_hex(fault_addr, buf, sizeof(buf));
            write_line(buf);
            print_entry_info(entry);
            write_str("Offset:          ");
            size_to_str(fault - user_start, buf, sizeof(buf));
            write_str(buf);
            write_line(" byte(s) from start (within buffer)");
        }
    } else {
        write_line("MGUARD: SIGSEGV at unknown address");
        print_separator();
        write_str("Fault address:   ");
        ptr_to_hex(fault_addr, buf, sizeof(buf));
        write_line(buf);
    }

    print_separator();

    /* Re-raise signal for core dump */
    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
}

/*
 * SIGBUS handler - called on bus error (e.g., file mapping beyond EOF).
 */
static void sigbus_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)sig;
    (void)ucontext;

    void *fault_addr = info->si_addr;
    char buf[32];

    alloc_entry_t *entry = registry_lookup_containing(fault_addr);

    print_separator();

    if (entry) {
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
    } else {
        write_line("MGUARD: SIGBUS at unknown address");
        print_separator();
        write_str("Fault address:   ");
        ptr_to_hex(fault_addr, buf, sizeof(buf));
        write_line(buf);
    }

    print_separator();

    signal(SIGBUS, SIG_DFL);
    raise(SIGBUS);
}

void report_init(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);

    /* Also handle SIGBUS for file mapping issues */
    sa.sa_sigaction = sigbus_handler;
    sigaction(SIGBUS, &sa, NULL);
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

    abort();
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

    abort();
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

    abort();
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

    abort();
}
