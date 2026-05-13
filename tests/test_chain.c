/*
 * Test signal handler chaining.
 *
 * Verifies that mguard chains to previously installed handlers
 * when a fault occurs outside mguard-managed memory.
 *
 * The test installs another SIGSEGV handler and then rearms mguard so the
 * custom handler is the handler mguard chains to for untracked faults.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>

static sigjmp_buf jump_buf;
static volatile int handler_called = 0;
static volatile void *fault_addr_received = NULL;

/* Custom SIGSEGV handler mguard should chain to for untracked faults. */
static void custom_sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)sig;
    (void)ucontext;

    handler_called = 1;
    fault_addr_received = info->si_addr;

    /* Recover from the fault */
    siglongjmp(jump_buf, 1);
}

static void install_custom_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = custom_sigsegv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, NULL) < 0) {
        perror("sigaction");
        _exit(1);
    }
}

static void rearm_mguard_handler(void) {
    void (*report_init_fn)(void) = dlsym(RTLD_DEFAULT, "report_init");
    if (!report_init_fn) {
        fprintf(stderr, "FAIL: report_init not found\n");
        exit(1);
    }
    report_init_fn();
}

/*
 * Trigger a SIGSEGV at an address NOT managed by mguard.
 * mguard should chain to our handler.
 */
static void trigger_non_mguard_fault(void) {
    /* Create a page and make it inaccessible */
    void *page = mmap(NULL, 4096, PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    /*
     * This is raw mmap, NOT through mguard's interposed mmap,
     * because PROT_NONE pages aren't tracked by mguard.
     * When we fault here, mguard won't find it in registry
     * and should chain to our handler.
     */

    if (sigsetjmp(jump_buf, 1) == 0) {
        /* First time - trigger the fault */
        volatile char *p = (volatile char *)page;
        (void)*p;  /* SIGSEGV: reading from PROT_NONE page */

        /* Should not reach here */
        fprintf(stderr, "FAIL: No fault occurred\n");
        exit(1);
    }

    /* Returned from siglongjmp - handler was called */
    munmap(page, 4096);
}

int main(void) {
    printf("Testing signal handler chaining...\n");

    /* Do a normal mguard allocation to ensure mguard is active */
    void *p = malloc(100);
    if (!p) {
        fprintf(stderr, "FAIL: malloc failed\n");
        return 1;
    }
    memset(p, 'A', 100);
    free(p);

    printf("mguard is active, triggering fault in non-mguard memory...\n");

    install_custom_handler();
    rearm_mguard_handler();

    /* Reset state */
    handler_called = 0;
    fault_addr_received = NULL;

    /* Trigger fault in memory mguard doesn't manage */
    trigger_non_mguard_fault();

    /* Verify our handler was called (chained to) */
    if (!handler_called) {
        fprintf(stderr, "FAIL: Custom handler was not called\n");
        return 1;
    }

    printf("PASS: Handler chaining works correctly\n");
    printf("  - Custom handler was called: yes\n");
    printf("  - Fault address received: %p\n", fault_addr_received);

    return 0;
}
