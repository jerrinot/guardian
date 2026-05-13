/*
 * Test: recoverable non-mguard SIGSEGV does not disable mguard reporting.
 *
 * The test first triggers a SIGSEGV outside mguard-owned memory and recovers
 * through a previously installed handler. It then triggers a real mguard
 * overflow. The detection wrapper should see the mguard overflow report.
 */
#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static sigjmp_buf jump_buf;
static volatile sig_atomic_t handler_called = 0;
static volatile sig_atomic_t fault_stage = 0;

static void custom_sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)sig;
    (void)info;
    (void)ucontext;

    if (fault_stage != 1) {
        const char msg[] = "FAIL: custom handler received mguard-owned fault\n";
        ssize_t ret __attribute__((unused)) = write(STDERR_FILENO, msg, sizeof(msg) - 1);
        _exit(2);
    }

    handler_called = 1;
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

static void trigger_recoverable_non_mguard_fault(void) {
    void *page = mmap(NULL, 4096, PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    if (sigsetjmp(jump_buf, 1) == 0) {
        fault_stage = 1;
        volatile char *p = (volatile char *)page;
        (void)*p;
        fprintf(stderr, "FAIL: no non-mguard fault occurred\n");
        exit(1);
    }

    fault_stage = 2;
    munmap(page, 4096);
}

int main(void) {
    install_custom_handler();
    rearm_mguard_handler();

    trigger_recoverable_non_mguard_fault();
    if (!handler_called) {
        fprintf(stderr, "FAIL: custom handler was not called\n");
        return 1;
    }

    volatile char *buf = malloc(100);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    buf[4096] = 'X';
    free((void *)buf);
    return 0;
}
