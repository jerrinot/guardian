/*
 * Test: tracked mremap rejects unsupported semantics instead of silently
 * changing Linux mremap contracts.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define FAIL(msg) do { fprintf(stderr, "FAIL: %s\n", msg); return 1; } while (0)

static int expect_failed_mremap(void *p, size_t old_size, size_t new_size,
                               int flags, void *fixed_addr, int expected_errno) {
    errno = 0;
    void *r;
    if (flags & MREMAP_FIXED) {
        r = mremap(p, old_size, new_size, flags, fixed_addr);
    } else {
        r = mremap(p, old_size, new_size, flags);
    }
    return r == MAP_FAILED && errno == expected_errno;
}

int main(void) {
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (page_size == 0) {
        page_size = 4096;
    }

    char *p = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("anonymous mmap failed");
    }
    memset(p, 'A', page_size);

    if (!expect_failed_mremap(p, page_size, page_size * 2, 0, NULL, ENOMEM)) {
        FAIL("mremap without MREMAP_MAYMOVE did not fail with ENOMEM");
    }
    if (p[0] != 'A' || p[page_size - 1] != 'A') {
        FAIL("mapping changed after failed in-place mremap");
    }

#ifdef MREMAP_DONTUNMAP
    if (!expect_failed_mremap(p, page_size, page_size,
                              MREMAP_MAYMOVE | MREMAP_DONTUNMAP,
                              NULL, EOPNOTSUPP)) {
        FAIL("tracked MREMAP_DONTUNMAP did not fail with EOPNOTSUPP");
    }
    if (p[0] != 'A' || p[page_size - 1] != 'A') {
        FAIL("mapping changed after failed DONTUNMAP mremap");
    }
#endif

    void *target = mmap(NULL, page_size * 2, PROT_NONE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (target == MAP_FAILED) {
        FAIL("target reservation failed");
    }
    if (!expect_failed_mremap(p, page_size, page_size * 2,
                              MREMAP_MAYMOVE | MREMAP_FIXED, target, ENOMEM)) {
        FAIL("tracked MREMAP_FIXED did not fail with ENOMEM");
    }
    munmap(target, page_size * 2);

    char *grown = mremap(p, page_size, page_size * 2, MREMAP_MAYMOVE);
    if (grown == MAP_FAILED) {
        FAIL("MREMAP_MAYMOVE anonymous grow failed");
    }
    if (grown[0] != 'A' || grown[page_size - 1] != 'A') {
        FAIL("anonymous data was not preserved across supported mremap");
    }
    memset(grown + page_size, 'B', page_size);
    if (munmap(grown, page_size * 2) != 0) {
        FAIL("grown anonymous munmap failed");
    }

    p = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("anonymous mmap for failed grow failed");
    }
    memset(p, 'Z', page_size);
    errno = 0;
    char *failed = mremap(p, page_size, SIZE_MAX - 8, MREMAP_MAYMOVE);
    if (failed != MAP_FAILED || errno != ENOMEM) {
        FAIL("huge MREMAP_MAYMOVE did not fail with ENOMEM");
    }
    if (p[0] != 'Z' || p[page_size - 1] != 'Z') {
        FAIL("mapping changed after failed huge mremap");
    }
    if (munmap(p, page_size) != 0) {
        FAIL("failed huge mremap mapping munmap failed");
    }

    p = mmap(NULL, page_size * 3, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("anonymous mmap for interior mremap failed");
    }
    memset(p, 'I', page_size * 3);
    errno = 0;
    char *interior = mremap(p + page_size, page_size, page_size * 2,
                            MREMAP_MAYMOVE);
    if (interior != MAP_FAILED || errno != EINVAL) {
        FAIL("interior tracked mremap did not fail with EINVAL");
    }
    if (p[0] != 'I' || p[page_size] != 'I' || p[page_size * 3 - 1] != 'I') {
        FAIL("mapping changed after failed interior mremap");
    }
    if (munmap(p, page_size * 3) != 0) {
        FAIL("interior mremap mapping munmap failed");
    }

    p = mmap(NULL, page_size * 2, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("anonymous mmap for old_size mismatch failed");
    }
    memset(p, 'C', page_size * 2);
    if (!expect_failed_mremap(p, page_size, page_size * 3,
                              MREMAP_MAYMOVE, NULL, EINVAL)) {
        FAIL("old_size mismatch mremap did not fail with EINVAL");
    }
    if (p[0] != 'C' || p[page_size * 2 - 1] != 'C') {
        FAIL("mapping changed after failed old_size mismatch mremap");
    }
    if (munmap(p, page_size * 2) != 0) {
        FAIL("old_size mismatch mapping munmap failed");
    }

    p = mmap(NULL, page_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("read-only anonymous mmap failed");
    }
    if (!expect_failed_mremap(p, page_size, page_size * 2,
                              MREMAP_MAYMOVE, NULL, EOPNOTSUPP)) {
        FAIL("read-only tracked mremap did not fail with EOPNOTSUPP");
    }
    if (p[0] != 0 || munmap(p, page_size) != 0) {
        FAIL("read-only mapping changed after failed mremap");
    }

    char tmpfile[] = "/tmp/mguard_mremap_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) {
        FAIL("mkstemp failed");
    }
    if (ftruncate(fd, (off_t)page_size * 2) != 0) {
        close(fd);
        unlink(tmpfile);
        FAIL("ftruncate failed");
    }

    char *fp = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (fp == MAP_FAILED) {
        close(fd);
        unlink(tmpfile);
        FAIL("file mmap failed");
    }
    fp[0] = 'X';

    char *grown_fp = mremap(fp, page_size, page_size * 2, MREMAP_MAYMOVE);
    if (grown_fp == MAP_FAILED) {
        close(fd);
        unlink(tmpfile);
        FAIL("tracked private file-backed mremap failed");
    }
    if (grown_fp[0] != 'X') {
        close(fd);
        unlink(tmpfile);
        FAIL("private file mapping changed after mremap");
    }
    grown_fp[page_size] = 'Y';
    if (munmap(grown_fp, page_size * 2) != 0) {
        close(fd);
        unlink(tmpfile);
        FAIL("grown private file mapping munmap failed");
    }

    if (ftruncate(fd, (off_t)page_size) != 0) {
        close(fd);
        unlink(tmpfile);
        FAIL("second ftruncate failed");
    }
    fp = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (fp == MAP_FAILED) {
        close(fd);
        unlink(tmpfile);
        FAIL("shared file mmap failed");
    }
    fp[0] = 'Q';
    char *same_fp = mremap(fp, page_size, page_size, MREMAP_MAYMOVE);
    if (same_fp != fp) {
        close(fd);
        unlink(tmpfile);
        FAIL("same-size file-backed mremap did not return original address");
    }
    if (same_fp[0] != 'Q') {
        close(fd);
        unlink(tmpfile);
        FAIL("same-size file-backed mremap changed data");
    }
    if (munmap(same_fp, page_size) != 0) {
        close(fd);
        unlink(tmpfile);
        FAIL("same-size file-backed mapping munmap failed");
    }

    fp = mmap(NULL, 64, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (fp == MAP_FAILED) {
        close(fd);
        unlink(tmpfile);
        FAIL("small shared file mmap failed");
    }
    fp[0] = 'S';
    char *resized_fp = mremap(fp, 64, 384, MREMAP_MAYMOVE);
    if (resized_fp == MAP_FAILED) {
        close(fd);
        unlink(tmpfile);
        FAIL("small shared file-backed mremap failed");
    }
    if (resized_fp[0] != 'S') {
        close(fd);
        unlink(tmpfile);
        FAIL("small shared file mapping changed after mremap");
    }
    resized_fp[383] = 'T';
    if (munmap(resized_fp, 384) != 0) {
        close(fd);
        unlink(tmpfile);
        FAIL("resized shared file mapping munmap failed");
    }

    close(fd);
    unlink(tmpfile);
    return 0;
}
