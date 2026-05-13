/*
 * Test: safe mmap operations in MGUARD_PROTECT_BELOW mode
 */
#include <sys/mman.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-50s ", name); fflush(stdout); } while (0)
#define PASS() do { printf("[PASS]\n"); } while (0)
#define FAIL(msg) do { printf("[FAIL] %s\n", msg); return 1; } while (0)

int main(void) {
    printf("=== mmap protect-below tests ===\n");

    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) page = 4096;

    TEST("page-sized writable mapping");
    {
        char *p = mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) FAIL("mmap failed");
        p[0] = 'A';
        p[page - 1] = 'Z';
        if (munmap(p, (size_t)page) != 0) FAIL("munmap failed");
        PASS();
    }

    TEST("non-page writable mapping");
    {
        size_t size = 1000;
        char *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) FAIL("mmap failed");
        memset(p, 'B', size);
        if (p[0] != 'B' || p[size - 1] != 'B') FAIL("data corruption");
        if (munmap(p, size) != 0) FAIL("munmap failed");
        PASS();
    }

    TEST("read-only mapping");
    {
        size_t size = 1000;
        char *p = mmap(NULL, size, PROT_READ,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) FAIL("mmap failed");
        if (p[0] != 0 || p[size - 1] != 0) FAIL("not zeroed");
        if (munmap(p, size) != 0) FAIL("munmap failed");
        PASS();
    }

    TEST("PROT_NONE mapping");
    {
        void *p = mmap(NULL, 1000, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) FAIL("mmap failed");
        if (munmap(p, 1000) != 0) FAIL("munmap failed");
        PASS();
    }

    TEST("file-backed mapping");
    {
        char tmpfile[] = "/tmp/mguard_mmap_below_XXXXXX";
        int fd = mkstemp(tmpfile);
        if (fd < 0) FAIL("mkstemp failed");
        unlink(tmpfile);

        char data[4096];
        memset(data, 'F', sizeof(data));
        if (write(fd, data, sizeof(data)) != (ssize_t)sizeof(data)) {
            close(fd);
            FAIL("write failed");
        }

        char *p = mmap(NULL, sizeof(data), PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (p == MAP_FAILED) FAIL("file mmap failed");
        if (p[0] != 'F' || p[sizeof(data) - 1] != 'F') FAIL("wrong file data");
        if (munmap(p, sizeof(data)) != 0) FAIL("munmap failed");
        PASS();
    }

    printf("=== All mmap protect-below tests passed! ===\n");
    return 0;
}
