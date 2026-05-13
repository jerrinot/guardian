/*
 * Test: one thread inside mguard's SIGSEGV handler must not suppress another
 * thread's mguard report.
 *
 * This runs in MGUARD_JVM=1 mode and wraps mguard's handler with an outer
 * handler to emulate a signal-chain owner. The first thread triggers a
 * use-after-free and stays inside the outer handler after mguard returns. The
 * second thread then triggers an overflow. With a process-global reentry flag,
 * mguard skips the second report; with a TLS flag, the overflow is reported.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static struct sigaction mguard_sigsegv_action;
static int first_thread_ready_pipe[2] = {-1, -1};
static __thread int fault_role = 0;

static void call_mguard_sigsegv(int sig, siginfo_t *info, void *ucontext) {
    if (mguard_sigsegv_action.sa_flags & SA_SIGINFO) {
        mguard_sigsegv_action.sa_sigaction(sig, info, ucontext);
    } else if (mguard_sigsegv_action.sa_handler &&
               mguard_sigsegv_action.sa_handler != SIG_DFL &&
               mguard_sigsegv_action.sa_handler != SIG_IGN) {
        mguard_sigsegv_action.sa_handler(sig);
    }
}

static void outer_sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    call_mguard_sigsegv(sig, info, ucontext);

    if (fault_role == 1) {
        char ready = '1';
        ssize_t ret __attribute__((unused)) = write(first_thread_ready_pipe[1], &ready, 1);
        for (;;) {
        }
    }

    if (fault_role == 2) {
        _exit(0);
    }

    _exit(2);
}

static void install_wrapped_mguard_handler(void) {
    void (*report_init_fn)(void) = dlsym(RTLD_DEFAULT, "report_init");
    if (!report_init_fn) {
        fprintf(stderr, "FAIL: report_init not found\n");
        exit(1);
    }

    report_init_fn();
    if (sigaction(SIGSEGV, NULL, &mguard_sigsegv_action) < 0) {
        perror("sigaction get");
        exit(1);
    }

    struct sigaction outer;
    memset(&outer, 0, sizeof(outer));
    outer.sa_sigaction = outer_sigsegv_handler;
    outer.sa_flags = SA_SIGINFO;
    sigemptyset(&outer.sa_mask);
    if (sigaction(SIGSEGV, &outer, NULL) < 0) {
        perror("sigaction set");
        exit(1);
    }
}

static void *first_thread(void *arg) {
    (void)arg;
    fault_role = 1;

    volatile char *buf = malloc(100);
    if (!buf) {
        _exit(3);
    }
    memset((void *)buf, 'A', 100);
    free((void *)buf);

    volatile char c = buf[50];
    (void)c;
    _exit(4);
}

static void *second_thread(void *arg) {
    (void)arg;
    fault_role = 2;

    volatile char *buf = malloc(100);
    if (!buf) {
        _exit(5);
    }

    buf[4096] = 'X';
    _exit(6);
}

static void wait_for_first_thread_handler(void) {
    char ready;
    ssize_t n;

    do {
        n = read(first_thread_ready_pipe[0], &ready, 1);
    } while (n < 0 && errno == EINTR);

    if (n != 1) {
        perror("read first-thread ready");
        exit(1);
    }
}

int main(void) {
    if (pipe(first_thread_ready_pipe) != 0) {
        perror("pipe");
        return 1;
    }

    install_wrapped_mguard_handler();
    alarm(10);

    pthread_t first;
    if (pthread_create(&first, NULL, first_thread, NULL) != 0) {
        perror("pthread_create first");
        return 1;
    }

    wait_for_first_thread_handler();

    pthread_t second;
    if (pthread_create(&second, NULL, second_thread, NULL) != 0) {
        perror("pthread_create second");
        return 1;
    }

    pthread_join(second, NULL);
    return 1;
}
