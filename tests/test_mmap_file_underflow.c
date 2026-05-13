/*
 * Test: file-backed mmap underflow detection
 * This should trigger SIGSEGV when mguard is active with MGUARD_PROTECT_BELOW=1.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    char tmpfile[] = "/tmp/mguard_file_underflow_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    unlink(tmpfile);

    char data[4096];
    memset(data, 'A', sizeof(data));
    if (write(fd, data, sizeof(data)) != (ssize_t)sizeof(data)) {
        perror("write");
        close(fd);
        return 1;
    }

    volatile char *buf = mmap(NULL, sizeof(data), PROT_READ | PROT_WRITE,
                              MAP_PRIVATE, fd, 0);
    close(fd);
    if (buf == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    if (buf[0] != 'A') {
        fprintf(stderr, "wrong file data\n");
        return 1;
    }

    /*
     * One byte before the returned file mapping should hit the leading guard
     * page in MGUARD_PROTECT_BELOW mode.
     */
    buf[-1] = 'X';

    munmap((void *)buf, sizeof(data));
    return 0;
}
