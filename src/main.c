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

typedef struct {
    Elf32_Word num_relocs;
    Elf32_Addr got_address;
    Elf32_Word got_size;
} efi_relocation_hdr_t;

typedef struct {
    Elf32_Addr address;
    Elf32_Word type;
    Elf32_Word sym_value;
} efi_relocation_t;

static Elf32_Phdr *phdr_text = NULL;
static Elf32_Phdr *phdr_data = NULL;
static Elf32_Ehdr *g_ehdr = NULL;
static uint32_t coff_alignment = 0x20;

static efi_relocation_hdr_t elochdr = {0};
static efi_relocation_t *efirelocs = NULL;
static size_t max_efirelocs = 0;

static inline uint32_t coff_align(uint32_t offset) {
  return (offset + coff_alignment - 1) & ~(coff_alignment - 1);
}

static efi_relocation_t* create_efireloc(void) {
    if (elochdr.num_relocs >= max_efirelocs) {
        efi_relocation_t *new_efirelocs = realloc(efirelocs, (max_efirelocs + 10000)*sizeof(*efirelocs));
        if (!new_efirelocs)
            return NULL;

        efirelocs = new_efirelocs;
        max_efirelocs += 10000;
    }

    return &efirelocs[elochdr.num_relocs++];
}

static int parse_elf(const char *filename) {
    int rc;
    void *buf;
    size_t bufsz;
    Elf32_Ehdr *ehdr;
    Elf32_Shdr *shdr;
    Elf32_Phdr *phdr;

    rc = file_to_buf(filename, (void**)&buf, &bufsz);
    if (rc) {
        return -1;
    }
    ehdr = buf;
    g_ehdr = ehdr;

    elf_for_every_phdr(buf, ehdr, phdr) {
        if (phdr->p_type != PT_LOAD)
            continue;

        if ((phdr->p_flags & (PF_R|PF_X)) == (PF_R|PF_X)) {
            assert(phdr_text==NULL);
            phdr_text = phdr;
        }

        else if ((phdr->p_flags & (PF_R|PF_W)) == (PF_R|PF_W)) {
            assert(phdr_data==NULL);
            phdr_data = phdr;
        }

        else {
            assert(0);
        }

        if (phdr->p_align > coff_alignment)
            coff_alignment = phdr->p_align;
    }

    if (!phdr_text || !phdr_data) {
        fprintf(stderr, "Can't find program headers\n");
        return -1;
    }

    Elf32_Shdr *shstrtabsec = buf + ehdr->e_shoff + ehdr->e_shstrndx * ehdr->e_shentsize;
    const char *shstrtab = buf + shstrtabsec->sh_offset;
    elf_for_every_section(buf, ehdr, shdr) {
        const char *secname = (void*)(shstrtab) + shdr->sh_name;
        if(!strcmp(secname, ".got")) {
            elochdr.got_address = shdr->sh_addr;
            elochdr.got_size = shdr->sh_size;
            break;
        }
    }

    const char *strtab = NULL;
    elf_for_every_section(buf, ehdr, shdr) {
        if (shdr->sh_type == SHT_STRTAB) {
            strtab = buf + shdr->sh_offset;
            break;
        }
    }
    if (strtab==NULL) {
        fprintf(stderr, "Can't find strtab\n");
        return -EINVAL;
    }

    int secidx = -1;
    elf_for_every_section(buf, ehdr, shdr) {
        secidx++;
        if (shdr->sh_type != SHT_REL && shdr->sh_type != SHT_RELA)
            continue;

        if (shdr->sh_type == SHT_RELA) {
            fprintf(stderr, "[%d] RELA relocation are not supported\n", secidx);
            return -EINVAL;
        }

        Elf32_Shdr *symshdr = buf + ehdr->e_shoff + ehdr->e_shentsize*(shdr->sh_link);
        Elf32_Shdr *dstshdr = buf + ehdr->e_shoff + ehdr->e_shentsize*(shdr->sh_info);

        if (!(dstshdr->sh_flags & SHF_ALLOC))
            continue;

        Elf32_Rel *rel;
        int relidx = -1;
        elf_for_every_relocation(buf, shdr, rel) {
            relidx++;
            Elf32_Addr symoffset = ELF32_R_SYM(rel->r_info);
            Elf32_Word type = ELF32_R_TYPE(rel->r_info);

            if (symoffset > (symshdr->sh_size / sizeof(Elf32_Sym))) {
                fprintf(stderr, "[%d][%d] Invalid symbol offset\n", secidx, relidx);
                return -EINVAL;
            }

            if (rel->r_offset-dstshdr->sh_addr > dstshdr->sh_size - sizeof(uint32_t)) {
                fprintf(stderr, "[%d][%d] Invalid relocation offset\n", secidx, relidx);
                continue;
            }

            Elf32_Sym *sym = ((Elf32_Sym*)(buf + symshdr->sh_offset)) + symoffset;
            if(sym->st_shndx == SHN_UNDEF) {
                continue;
            }

            switch(type) {
                case R_ARM_NONE:
                    // nothing to do
                    break;

                case R_ARM_TARGET2:
                case R_ARM_CALL:
                case R_ARM_JUMP24:
                case R_ARM_THM_PC11:
                case R_ARM_THM_PC22:
                case R_ARM_THM_JUMP24:
                case R_ARM_PREL31:
                case R_ARM_REL32:
                case R_ARM_GOTPC:
                case R_ARM_GOT32:
                    // these are PC-relative
                    break;

                case R_ARM_ABS32:
                case R_ARM_TARGET1:
                case R_ARM_MOVW_ABS_NC:
                case R_ARM_MOVT_ABS:
                case R_ARM_THM_MOVW_ABS_NC:
                case R_ARM_THM_MOVT_ABS: {
                    efi_relocation_t *efirel = create_efireloc();
                    assert(efirel);
                    efirel->address = rel->r_offset;
                    efirel->type = type;
                    efirel->sym_value = sym->st_value;
                    break;
                }

                default:
                    fprintf(stderr, "Unsupported relocation type %d\n", type);
                    return -1;
            }
        }
    }

    // GCC doesn't emit relocations for these so generate them ourselves
    elf_for_every_section(buf, ehdr, shdr) {
        if (shdr->sh_type == SHT_SYMTAB) {
            Elf32_Sym *symtab = (Elf32_Sym*)(buf + shdr->sh_offset);

            Elf32_Sym *sym;
            for(
                sym = symtab;
                (void*)sym < ((void*)symtab) + shdr->sh_size;
                sym = ((void*)sym) + shdr->sh_entsize
                )
            {
                const char *symname = strtab + sym->st_name;

                if (ends_with(symname, "_from_arm")) {
                    efi_relocation_t *efirel = create_efireloc();
                    assert(efirel);
                    efirel->address = sym->st_value + 4;
                    efirel->type = R_ARM_ABS32;
                    efirel->sym_value = sym->st_value;
                }
            }
        }
    }

    return 0;
}

static int write_efi(const char *filename) {
    int fd;
    EFI_IMAGE_DOS_HEADER dosHdr;
    EFI_IMAGE_OPTIONAL_HEADER_UNION ntHdr;
    EFI_IMAGE_SECTION_HEADER secHdrESR;
    EFI_IMAGE_SECTION_HEADER secHdrText;
    EFI_IMAGE_SECTION_HEADER secHdrData;

    // the default linker script sets this to 0x10000
    // but as far as I know that's only for MMU compatibility
    // and not for code operability.
    // so set this to the minimum UEFI page size to save some space.
    coff_alignment = 0x1000;

    off_t table_offset = sizeof(EFI_IMAGE_DOS_HEADER) + 0x40 + sizeof (EFI_IMAGE_NT_HEADERS32);
    size_t table_size = 3 * sizeof(EFI_IMAGE_SECTION_HEADER);

    off_t selfreloc_offset = MAX(coff_align(table_offset + table_size), coff_alignment);
    size_t selfreloc_size = sizeof(efi_relocation_hdr_t) + elochdr.num_relocs * sizeof(efi_relocation_t);

    uint32_t text_address = coff_align(selfreloc_offset + selfreloc_size);
    off_t loading_offset = text_address - phdr_text->p_vaddr;

    uint32_t data_addr_real = phdr_data->p_vaddr + loading_offset;
    uint32_t data_addr_rounded = ROUNDDOWN(data_addr_real, coff_alignment);
    uint32_t data_addr_diff = data_addr_real - data_addr_rounded;

    memset(&secHdrESR, 0, sizeof(secHdrESR));
    strcpy((char *)secHdrESR.Name, "esr");
    secHdrESR.Misc.VirtualSize = coff_align(selfreloc_size);
    secHdrESR.VirtualAddress = selfreloc_offset;
    secHdrESR.SizeOfRawData = coff_align(selfreloc_size);
    secHdrESR.PointerToRawData = selfreloc_offset;
    secHdrESR.Characteristics = EFI_IMAGE_SCN_CNT_INITIALIZED_DATA
            | EFI_IMAGE_SCN_MEM_READ;

    memset(&secHdrText, 0, sizeof(secHdrText));
    strcpy((char *)secHdrText.Name, ".text");
    secHdrText.Misc.VirtualSize = coff_align(phdr_text->p_memsz);
    secHdrText.VirtualAddress = phdr_text->p_vaddr + loading_offset;
    secHdrText.SizeOfRawData = coff_align(phdr_text->p_memsz);
    secHdrText.PointerToRawData = secHdrText.VirtualAddress;
    secHdrText.Characteristics = EFI_IMAGE_SCN_CNT_CODE
            | EFI_IMAGE_SCN_MEM_EXECUTE
            | EFI_IMAGE_SCN_MEM_WRITE
            | EFI_IMAGE_SCN_MEM_READ;

    memset(&secHdrData, 0, sizeof(secHdrData));
    strcpy((char *)secHdrData.Name, ".data");
    secHdrData.Misc.VirtualSize = coff_align(phdr_data->p_memsz + data_addr_diff);
    secHdrData.VirtualAddress = phdr_data->p_vaddr + loading_offset - data_addr_diff;
    secHdrData.SizeOfRawData = coff_align(phdr_data->p_memsz + data_addr_diff);
    secHdrData.PointerToRawData = secHdrData.VirtualAddress;
    secHdrData.Characteristics = EFI_IMAGE_SCN_CNT_INITIALIZED_DATA
            | EFI_IMAGE_SCN_MEM_WRITE
            | EFI_IMAGE_SCN_MEM_READ;

    fd = open(filename, O_WRONLY|O_TRUNC|O_CREAT, 0644);
    if (fd<0) {
        fprintf(stderr, "can't open %s: %d\n", filename, errno);
        return -1;
    }

    // DOS header
    memset(&dosHdr, 0, sizeof(dosHdr));
    dosHdr.e_magic = EFI_IMAGE_DOS_SIGNATURE;
    dosHdr.e_lfanew = sizeof(EFI_IMAGE_DOS_HEADER) + 0x40;
    write(fd, &dosHdr, sizeof(dosHdr));

    // NT header
    memset(&ntHdr, 0, sizeof(ntHdr));
    ntHdr.Pe32.Signature = EFI_IMAGE_NT_SIGNATURE;
    ntHdr.Pe32.FileHeader.Machine = EFI_IMAGE_MACHINE_ARMT;
    ntHdr.Pe32.OptionalHeader.Magic = EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC;

    ntHdr.Pe32.FileHeader.NumberOfSections = 3;
    ntHdr.Pe32.FileHeader.TimeDateStamp = 0;
    ntHdr.Pe32.FileHeader.PointerToSymbolTable = 0;
    ntHdr.Pe32.FileHeader.NumberOfSymbols = 0;
    ntHdr.Pe32.FileHeader.SizeOfOptionalHeader = sizeof(ntHdr.Pe32.OptionalHeader);
    ntHdr.Pe32.FileHeader.Characteristics = EFI_IMAGE_FILE_EXECUTABLE_IMAGE
      | EFI_IMAGE_FILE_LINE_NUMS_STRIPPED
      | EFI_IMAGE_FILE_LOCAL_SYMS_STRIPPED
      | EFI_IMAGE_FILE_32BIT_MACHINE;

    ntHdr.Pe32.OptionalHeader.SizeOfCode = coff_align(phdr_text->p_memsz);
    ntHdr.Pe32.OptionalHeader.SizeOfInitializedData = coff_align(phdr_data->p_memsz);
    ntHdr.Pe32.OptionalHeader.SizeOfUninitializedData = 0;
    ntHdr.Pe32.OptionalHeader.AddressOfEntryPoint = g_ehdr->e_entry + loading_offset;

    ntHdr.Pe32.OptionalHeader.BaseOfCode = secHdrText.VirtualAddress;

    ntHdr.Pe32.OptionalHeader.BaseOfData = secHdrData.VirtualAddress;
    ntHdr.Pe32.OptionalHeader.ImageBase = 0;
    ntHdr.Pe32.OptionalHeader.SectionAlignment = coff_alignment;
    ntHdr.Pe32.OptionalHeader.FileAlignment = coff_alignment;
    ntHdr.Pe32.OptionalHeader.SizeOfImage = coff_align(secHdrData.VirtualAddress + secHdrData.SizeOfRawData);
    ntHdr.Pe32.OptionalHeader.Subsystem = EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION;

    ntHdr.Pe32.OptionalHeader.SizeOfHeaders = secHdrESR.PointerToRawData;
    ntHdr.Pe32.OptionalHeader.NumberOfRvaAndSizes = EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;

    lseek(fd, 0x40, SEEK_CUR);
    write(fd, &ntHdr, sizeof(ntHdr));

    // section headers
    lseek(fd, table_offset, SEEK_SET);
    write(fd, &secHdrESR, sizeof(secHdrESR));
    write(fd, &secHdrText, sizeof(secHdrText));
    write(fd, &secHdrData, sizeof(secHdrData));

    // esr
    lseek(fd, secHdrESR.PointerToRawData, SEEK_SET);
    write(fd, &elochdr, sizeof(efi_relocation_hdr_t));
    write(fd, efirelocs, elochdr.num_relocs * sizeof(efi_relocation_t));

    // .text
    lseek(fd, secHdrText.PointerToRawData, SEEK_SET);
    write(fd, ((void*)g_ehdr) + phdr_text->p_offset, phdr_text->p_filesz);

    // .data
    lseek(fd, secHdrData.PointerToRawData + data_addr_diff, SEEK_SET);
    write(fd, ((void*)g_ehdr) + phdr_data->p_offset, phdr_data->p_filesz);

    ftruncate(fd, ntHdr.Pe32.OptionalHeader.SizeOfImage);
    close(fd);

    return 0;
}

int main(int argc, char** argv) {
    const char *filename_elf;
    const char *filename_efi;
    int rc;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s IN OUT\n", argv[0]);
        return -EINVAL;
    }
    filename_elf = argv[1];
    filename_efi = argv[2];

    rc = parse_elf(filename_elf);
    if (rc) {
        fprintf(stderr, "Can't parse elf\n");
        return -1;
    }

    rc = write_efi(filename_efi);
    if (rc) {
        fprintf(stderr, "Can't write efi\n");
        return -1;
    }

    return 0;
}
