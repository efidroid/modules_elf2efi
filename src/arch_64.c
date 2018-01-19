#include <elf.h>

typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Rela Elf_Rela;
typedef Elf64_Rel  Elf_Rel;
typedef Elf64_Addr Elf_Addr;
typedef Elf64_Word Elf_Word;
typedef Elf64_Half Elf_Half;
typedef Elf64_Sym  Elf_Sym;
typedef Elf64_Xword Elf_Xword;
typedef Elf64_Sxword Elf_Sxword;

#define ELF_R_SYM ELF64_R_SYM
#define ELF_R_TYPE ELF64_R_TYPE
#define FN_SUFFIX _64
#define EFI_IMAGE_NT_HEADERS EFI_IMAGE_NT_HEADERS64
#define EFI_IMAGE_NT_OPTIONAL_HDR_MAGIC EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define Pe32Arch Pe32Plus
#define ELF2EFI_BITS 64

#include "arch.inc.c"
