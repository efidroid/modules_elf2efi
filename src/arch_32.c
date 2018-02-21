#include <elf-local.h>

typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Dyn  Elf_Dyn;
typedef Elf32_Rela Elf_Rela;
typedef Elf32_Rel  Elf_Rel;
typedef Elf32_Addr Elf_Addr;
typedef Elf32_Word Elf_Word;
typedef Elf32_Half Elf_Half;
typedef Elf32_Sym  Elf_Sym;
typedef Elf32_Xword Elf_Xword;
typedef Elf32_Sxword Elf_Sxword;

#define ELF_R_SYM ELF32_R_SYM
#define ELF_R_TYPE ELF32_R_TYPE
#define FN_SUFFIX _32
#define EFI_IMAGE_NT_HEADERS EFI_IMAGE_NT_HEADERS32
#define EFI_IMAGE_NT_OPTIONAL_HDR_MAGIC EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC
#define Pe32Arch Pe32
#define ELF2EFI_BITS 32

#include "arch.inc.c"
