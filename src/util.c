#include <util.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

off_t fdsize(int fd)
{
    off_t off;

    off = lseek(fd, 0L, SEEK_END);
    lseek(fd, 0L, SEEK_SET);

    return off;
}

int file_to_buf(const char* filename, void **out_buf, size_t *out_size) {
    char *buf;
    int fd;
    off_t filesize;
    ssize_t nbytes;

    // open file
    fd = open(filename, O_RDONLY);
    if (fd<0) {
        fprintf(stderr, "can't open %s: %d\n", filename, errno);
        return -1;
    }

    // get file size
    filesize = fdsize(fd);
    if(filesize<0)
        return -1;

    // allocate buffer
    buf = malloc(filesize);
    if (buf==NULL)
        return -1;

    // read file
    nbytes = read(fd, buf, filesize);
    if (nbytes != filesize) {
        free(buf);
        return -1;
    }

    // close file
    close(fd);

    *out_buf = buf;
    *out_size = filesize;

    return 0;
}

int buf_to_file(const char *filename, void *buf, size_t size) {
    int fd;
    ssize_t nbytes;

    fd = open(filename, O_WRONLY|O_TRUNC|O_CREAT, 0744);
    if (fd<0) {
        fprintf(stderr, "can't open %s: %d\n", filename, errno);
        return -1;
    }

    nbytes = write(fd, buf, size);
    if (nbytes != (ssize_t)size) {
        return -1;
    }

    close(fd);

    return 0;
}

int ends_with (const char* base, const char* str) {
    int blen = strlen(base);
    int slen = strlen(str);
    return (blen >= slen) && (0 == strcmp(base + blen - slen, str));
}

