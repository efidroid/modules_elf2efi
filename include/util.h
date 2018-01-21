#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>

#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define ROUNDDOWN(a, b) ((a) & ~((b)-1))

#define elf_for_every_phdr(buf, ehdr, phdr) \
    for ( \
         phdr = buf + ehdr->e_phoff; \
         (void*)phdr <= buf + ehdr->e_phoff + ehdr->e_phentsize*(ehdr->e_phnum-1); \
         phdr = ((void*)phdr) + ehdr->e_phentsize)

#define elf_for_every_section(buf, ehdr, shdr) \
    for ( \
         shdr = buf + ehdr->e_shoff; \
         (void*)shdr <= buf + ehdr->e_shoff + ehdr->e_shentsize*(ehdr->e_shnum-1); \
         shdr = ((void*)shdr) + ehdr->e_shentsize)

#define elf_for_every_relocation(buf, shdr, rel) \
    for ( \
         rel = buf + shdr->sh_offset; \
         (void*)rel < buf + shdr->sh_offset + shdr->sh_size; \
         rel = ((void*)rel) + shdr->sh_entsize)

#define elf_for_every_relocation_dt(dt_rel, dt_relsz, dt_relent, rel) \
    for ( \
         rel = dt_rel; \
         (void*)rel < ((void*)dt_rel) + dt_relsz; \
         rel = ((void*)rel) + dt_relent)

off_t fdsize(int fd);
int file_to_buf(const char* filename, void **out_buf, size_t *out_size);
int buf_to_file(const char *filename, void *buf, size_t size);
int ends_with (const char* base, const char* str);

#endif
