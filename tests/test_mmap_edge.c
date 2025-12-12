/*
 * Test: mmap/munmap/mremap edge cases
 * Tests various mmap scenarios including file-backed, various protection modes.
 */
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#define TEST(name) do { printf("  %-50s ", name); fflush(stdout); } while(0)
#define PASS() do { printf("[PASS]\n"); } while(0)
#define FAIL(msg) do { printf("[FAIL] %s\n", msg); return 1; } while(0)
#define SKIP(msg) do { printf("[SKIP] %s\n", msg); } while(0)

#define KB (1024UL)
#define MB (1024UL * KB)

int main(void) {
    printf("=== mmap/munmap/mremap Edge Case Tests ===\n");

    /* Test 1: Basic anonymous mmap */
    TEST("anonymous mmap PROT_READ|PROT_WRITE");
    {
        char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) FAIL("mmap failed");
        memset(p, 'A', 4096);
        if (p[0] != 'A' || p[4095] != 'A') FAIL("data corruption");
        if (munmap(p, 4096) != 0) FAIL("munmap failed");
        PASS();
    }

    /* Test 2: Read-only anonymous mmap */
    TEST("anonymous mmap PROT_READ only");
    {
        char *p = mmap(NULL, 4096, PROT_READ,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) FAIL("mmap failed");
        /* Should be able to read (zeros for anonymous) */
        if (p[0] != 0) FAIL("not zeroed");
        if (munmap(p, 4096) != 0) FAIL("munmap failed");
        PASS();
    }

    /* Test 3: PROT_NONE anonymous mmap */
    TEST("anonymous mmap PROT_NONE");
    {
        char *p = mmap(NULL, 4096, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) FAIL("mmap failed");
        /* Cannot access - just verify mapping succeeded */
        if (munmap(p, 4096) != 0) FAIL("munmap failed");
        PASS();
    }

    /* Test 4: Large anonymous mmap */
    TEST("large anonymous mmap (100 MB)");
    {
        char *p = mmap(NULL, 100 * MB, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) FAIL("mmap failed");
        /* Sparse access */
        for (size_t i = 0; i < 100 * MB; i += MB) {
            p[i] = 'X';
        }
        if (munmap(p, 100 * MB) != 0) FAIL("munmap failed");
        PASS();
    }

    /* Test 5: Multiple small mmaps */
    TEST("multiple small mmaps (100 x 4KB)");
    {
        void *ptrs[100];
        for (int i = 0; i < 100; i++) {
            ptrs[i] = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (ptrs[i] == MAP_FAILED) FAIL("mmap failed");
            memset(ptrs[i], i, 4096);
        }
        for (int i = 0; i < 100; i++) {
            if (munmap(ptrs[i], 4096) != 0) FAIL("munmap failed");
        }
        PASS();
    }

    /* Test 6: Non-page-aligned size (should be rounded up) */
    TEST("non-page-aligned size (1000 bytes)");
    {
        char *p = mmap(NULL, 1000, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) FAIL("mmap failed");
        memset(p, 'B', 1000);
        /* Access last requested byte */
        if (p[999] != 'B') FAIL("data corruption");
        if (munmap(p, 1000) != 0) FAIL("munmap failed");
        PASS();
    }

    /* Test 7: mremap grow */
    TEST("mremap grow (4KB -> 8KB)");
    {
        char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) FAIL("mmap failed");
        memset(p, 'C', 4096);

        char *new_p = mremap(p, 4096, 8192, MREMAP_MAYMOVE);
        if (new_p == MAP_FAILED) FAIL("mremap failed");

        /* Verify original data */
        for (int i = 0; i < 4096; i++) {
            if (new_p[i] != 'C') FAIL("data corruption");
        }
        /* Write to new space */
        memset(new_p + 4096, 'D', 4096);

        if (munmap(new_p, 8192) != 0) FAIL("munmap failed");
        PASS();
    }

    /* Test 8: mremap shrink */
    TEST("mremap shrink (8KB -> 4KB)");
    {
        char *p = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) FAIL("mmap failed");
        memset(p, 'E', 8192);

        char *new_p = mremap(p, 8192, 4096, MREMAP_MAYMOVE);
        if (new_p == MAP_FAILED) FAIL("mremap failed");

        /* Verify data in smaller region */
        for (int i = 0; i < 4096; i++) {
            if (new_p[i] != 'E') FAIL("data corruption");
        }

        if (munmap(new_p, 4096) != 0) FAIL("munmap failed");
        PASS();
    }

    /* Test 9: mremap large grow */
    TEST("mremap large grow (1MB -> 10MB)");
    {
        char *p = mmap(NULL, 1 * MB, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) FAIL("mmap failed");
        memset(p, 'F', 1 * MB);

        char *new_p = mremap(p, 1 * MB, 10 * MB, MREMAP_MAYMOVE);
        if (new_p == MAP_FAILED) FAIL("mremap failed");

        /* Sparse verify original data */
        for (size_t i = 0; i < 1 * MB; i += 4096) {
            if (new_p[i] != 'F') FAIL("data corruption");
        }

        if (munmap(new_p, 10 * MB) != 0) FAIL("munmap failed");
        PASS();
    }

    /* Test 10: File-backed mmap */
    TEST("file-backed mmap");
    {
        /* Create temp file */
        char tmpfile[] = "/tmp/mguard_test_XXXXXX";
        int fd = mkstemp(tmpfile);
        if (fd < 0) {
            SKIP("cannot create temp file");
        } else {
            /* Write some data */
            char data[4096];
            memset(data, 'G', sizeof(data));
            if (write(fd, data, sizeof(data)) != sizeof(data)) {
                close(fd);
                unlink(tmpfile);
                FAIL("write failed");
            }

            /* Map the file */
            char *p = mmap(NULL, 4096, PROT_READ,
                          MAP_PRIVATE, fd, 0);
            if (p == MAP_FAILED) {
                close(fd);
                unlink(tmpfile);
                FAIL("mmap failed");
            }

            /* Verify content */
            for (int i = 0; i < 4096; i++) {
                if (p[i] != 'G') {
                    munmap(p, 4096);
                    close(fd);
                    unlink(tmpfile);
                    FAIL("data corruption");
                }
            }

            munmap(p, 4096);
            close(fd);
            unlink(tmpfile);
            PASS();
        }
    }

    /* Test 11: File-backed mmap read-write */
    TEST("file-backed mmap PROT_READ|PROT_WRITE");
    {
        char tmpfile[] = "/tmp/mguard_test_XXXXXX";
        int fd = mkstemp(tmpfile);
        if (fd < 0) {
            SKIP("cannot create temp file");
        } else {
            /* Extend file */
            if (ftruncate(fd, 4096) != 0) {
                close(fd);
                unlink(tmpfile);
                FAIL("ftruncate failed");
            }

            /* Map read-write */
            char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_SHARED, fd, 0);
            if (p == MAP_FAILED) {
                close(fd);
                unlink(tmpfile);
                FAIL("mmap failed");
            }

            /* Write through mapping */
            memset(p, 'H', 4096);
            msync(p, 4096, MS_SYNC);

            munmap(p, 4096);
            close(fd);
            unlink(tmpfile);
            PASS();
        }
    }

    /* Test 12: mmap with offset */
    TEST("file-backed mmap with offset");
    {
        char tmpfile[] = "/tmp/mguard_test_XXXXXX";
        int fd = mkstemp(tmpfile);
        if (fd < 0) {
            SKIP("cannot create temp file");
        } else {
            /* Create 8KB file with different data in each half */
            char data[8192];
            memset(data, 'I', 4096);
            memset(data + 4096, 'J', 4096);
            if (write(fd, data, sizeof(data)) != sizeof(data)) {
                close(fd);
                unlink(tmpfile);
                FAIL("write failed");
            }

            /* Map second half only */
            char *p = mmap(NULL, 4096, PROT_READ,
                          MAP_PRIVATE, fd, 4096);
            if (p == MAP_FAILED) {
                close(fd);
                unlink(tmpfile);
                FAIL("mmap failed");
            }

            /* Should contain 'J' */
            if (p[0] != 'J') {
                munmap(p, 4096);
                close(fd);
                unlink(tmpfile);
                FAIL("wrong data (offset not working)");
            }

            munmap(p, 4096);
            close(fd);
            unlink(tmpfile);
            PASS();
        }
    }

    /* Test 13: Multiple mmaps of same file */
    TEST("multiple mmaps of same file");
    {
        char tmpfile[] = "/tmp/mguard_test_XXXXXX";
        int fd = mkstemp(tmpfile);
        if (fd < 0) {
            SKIP("cannot create temp file");
        } else {
            if (ftruncate(fd, 4096) != 0) {
                close(fd);
                unlink(tmpfile);
                FAIL("ftruncate failed");
            }

            /* Create multiple mappings */
            void *ptrs[10];
            for (int i = 0; i < 10; i++) {
                ptrs[i] = mmap(NULL, 4096, PROT_READ,
                              MAP_PRIVATE, fd, 0);
                if (ptrs[i] == MAP_FAILED) {
                    close(fd);
                    unlink(tmpfile);
                    FAIL("mmap failed");
                }
            }

            for (int i = 0; i < 10; i++) {
                munmap(ptrs[i], 4096);
            }

            close(fd);
            unlink(tmpfile);
            PASS();
        }
    }

    /* Test 14: mmap works for various sizes
     * Note: With mguard, addresses may not be page-aligned for sub-page sizes
     * because mguard positions buffers for byte-precise overflow detection.
     */
    TEST("mmap various sizes work correctly");
    {
        size_t sizes[] = {1, 100, 1000, 4095, 4096, 4097, 8192, 10000};
        for (size_t i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
            char *p = mmap(NULL, sizes[i], PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p == MAP_FAILED) FAIL("mmap failed");
            /* Write to first and last byte to verify mapping is usable */
            p[0] = 'X';
            p[sizes[i] - 1] = 'Y';
            munmap(p, sizes[i]);
        }
        PASS();
    }

    /* Test 15: Rapid mmap/munmap cycles */
    TEST("rapid mmap/munmap cycles (1000 iterations)");
    {
        for (int i = 0; i < 1000; i++) {
            void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p == MAP_FAILED) FAIL("mmap failed");
            if (munmap(p, 4096) != 0) FAIL("munmap failed");
        }
        PASS();
    }

    /* Test 16: mmap chain with mremap */
    TEST("mmap chain with mremap");
    {
        char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) FAIL("mmap failed");
        *p = 'K';

        /* Chain of mremaps */
        for (size_t sz = 8192; sz <= 65536; sz += 4096) {
            p = mremap(p, sz - 4096, sz, MREMAP_MAYMOVE);
            if (p == MAP_FAILED) FAIL("mremap failed");
        }

        /* First byte should still be 'K' */
        if (*p != 'K') FAIL("data corruption");

        munmap(p, 65536);
        PASS();
    }

    printf("=== All mmap/munmap/mremap tests passed! ===\n");
    return 0;
}
