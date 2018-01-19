#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

#include <Base.h>
#include <PeImage.h>
#include <util.h>

extern int do_convert_32(void *buf, size_t bufsz, const char *filename_efi);
extern int do_convert_64(void *buf, size_t bufsz, const char *filename_efi);

int main(int argc, char** argv) {
    const char *filename_elf;
    const char *filename_efi;
    void *elf_buf;
    size_t elf_bufsz;
    int rc;
    unsigned char *ident;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s IN OUT\n", argv[0]);
        return -EINVAL;
    }
    filename_elf = argv[1];
    filename_efi = argv[2];

    rc = file_to_buf(filename_elf, (void**)&elf_buf, &elf_bufsz);
    if (rc) {
        fprintf(stderr, "can't read elf file\n");
        return -1;
    }
    ident = elf_buf;

    if (memcmp(ident, ELFMAG, SELFMAG)) {
        fprintf(stderr, "%s is not an elf file\n", filename_elf);
        free(elf_buf);
        return -1;
    }

    if (ident[EI_CLASS] == ELFCLASS32)
        rc = do_convert_32(elf_buf, elf_bufsz, filename_efi);
    else if (ident[EI_CLASS] == ELFCLASS64)
        rc = do_convert_64(elf_buf, elf_bufsz, filename_efi);
    else {
        fprintf(stderr, "unsupported ELF class %u\n", ident[EI_CLASS]);
        rc = -1;
    }

    free(elf_buf);

    return rc;
}
