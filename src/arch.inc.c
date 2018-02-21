#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>

#include <Base.h>
#include <PeImage.h>
#include <util.h>

#define __FN(fn, suffix) fn##suffix
#define _FN(fn, suffix) __FN(fn, suffix)
#define FN(fn) _FN(fn, FN_SUFFIX)

typedef struct {
    Elf_Word num_relocs;
    Elf_Addr got_address;
    Elf_Word got_size;
    Elf_Word elf_type;

    Elf_Addr text_base;
    Elf_Word text_size;
} efi_relocation_hdr_t;

typedef struct {
    Elf_Addr address;
    Elf_Word type;
    Elf_Word sym_value;
} efi_relocation_t;

static Elf_Phdr *phdr_text = NULL;
static Elf_Phdr *phdr_data = NULL;
static Elf_Ehdr *g_ehdr = NULL;
static Elf_Word coff_alignment = 0x20;
static Elf_Half g_machine;

static efi_relocation_hdr_t elochdr;
static efi_relocation_t *efirelocs = NULL;
static size_t max_efirelocs = 0;

static inline Elf_Addr coff_align(Elf_Addr offset) {
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

static int parse_reloc(int secidx, int relidx, Elf_Shdr *symshdr, Elf_Shdr *dstshdr,
                       Elf_Addr r_offset, Elf_Addr symoffset, Elf_Xword type, Elf_Sxword r_addend
           )
{
    Elf_Sym *sym = NULL;

    if (symshdr && symoffset > (symshdr->sh_size / sizeof(Elf_Sym))) {
        fprintf(stderr, "[%d][%d] Invalid symbol offset\n", secidx, relidx);
        return -EINVAL;
    }

    if (dstshdr && r_offset - dstshdr->sh_addr > dstshdr->sh_size - sizeof(Elf_Word)) {
        int64_t woffset = (int64_t)(r_offset) - dstshdr->sh_addr - dstshdr->sh_size;
        fprintf(stderr, "[%d][%d] type=%"PRIu64" Invalid relocation offset: 0x%08"PRIx64" (%"PRId64") off=%08"PRIx64" shaddr=%08"PRIx64" shsz=%08"PRIx64"\n",
            secidx, relidx, type, woffset, woffset,
            (uint64_t)r_offset, (uint64_t)dstshdr->sh_addr, (uint64_t)dstshdr->sh_size);
        return 0;
    }

    if (symshdr) {
        sym = ((Elf_Sym*)(((void*)g_ehdr) + symshdr->sh_offset)) + symoffset;
        if(sym->st_shndx == SHN_UNDEF) {
            return 0;
        }
    }

    int needs_reloc = 0;
    if (g_machine == EM_ARM) {
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
                needs_reloc = 1;
                break;
            }

            default:
                fprintf(stderr, "Unsupported relocation type %"PRIu64"\n", type);
                return -1;
        }
    }

    else if (g_machine == EM_X86_64) {
        switch(type) {
            case R_X86_64_NONE:
                // nothing to do
                break;

            case R_X86_64_GLOB_DAT:
                fprintf(stderr, "ignore R_X86_64_GLOB_DAT\n");
                break;

            case R_X86_64_RELATIVE: {
                needs_reloc = 1;
                break;
            }

            default:
                fprintf(stderr, "Unsupported relocation type %"PRIu64"\n", type);
                return -1;
        }
    }

    else {
        assert(0);
    }

    if (needs_reloc) {
        efi_relocation_t *efirel = create_efireloc();
        assert(efirel);
        efirel->address = r_offset;
        efirel->type = type;
        if (sym)
            efirel->sym_value = sym->st_value + r_addend;
    }

    return 0;
}

static int parse_elf(void *buf, size_t bufsz) {
    Elf_Ehdr *ehdr;
    Elf_Shdr *shdr;
    Elf_Phdr *phdr;
    Elf_Dyn *dyn = NULL;

    (void)(bufsz);

    ehdr = buf;
    g_ehdr = ehdr;

    g_machine = ehdr->e_machine;

    switch (g_machine) {
        case EM_X86_64:
        case EM_ARM:
            break;

        default:
            fprintf(stderr, "unsupported machine: %u\n", g_machine);
            return -1;
    }

    elf_for_every_phdr(buf, ehdr, phdr) {
        if (phdr->p_type == PT_LOAD) {
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

        else if (phdr->p_type == PT_DYNAMIC) {
            dyn = ((void*)ehdr) + phdr->p_offset;
        }
    }

    if (!phdr_text || !phdr_data) {
        fprintf(stderr, "Can't find program headers\n");
        return -1;
    }

    Elf_Shdr *shstrtabsec = buf + ehdr->e_shoff + ehdr->e_shstrndx * ehdr->e_shentsize;
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

    if (ehdr->e_type == ET_EXEC) {
        int secidx = -1;
        elf_for_every_section(buf, ehdr, shdr) {
            secidx++;

            if (shdr->sh_type != SHT_REL && shdr->sh_type != SHT_RELA)
                continue;

            if (shdr->sh_link > ehdr->e_shnum) {
                fprintf(stderr, "[%d] invalid section %d in sh_link\n", secidx, shdr->sh_link);
                return -1;
            }

            if (shdr->sh_info > ehdr->e_shnum) {
                fprintf(stderr, "[%d] invalid section %d in sh_info\n", secidx, shdr->sh_info);
                return -1;
            }

            Elf_Shdr *symshdr = buf + ehdr->e_shoff + ehdr->e_shentsize*(shdr->sh_link);
            Elf_Shdr *dstshdr = buf + ehdr->e_shoff + ehdr->e_shentsize*(shdr->sh_info);

            if (!(dstshdr->sh_flags & SHF_ALLOC))
                continue;

            if (shdr->sh_type == SHT_REL) {
                Elf_Rel *rel;
                int relidx = -1;
                elf_for_every_relocation(buf, shdr, rel) {
                    relidx++;
                    Elf_Addr r_offset = rel->r_offset;
                    Elf_Addr symoffset = ELF_R_SYM(rel->r_info);
                    Elf_Xword type = ELF_R_TYPE(rel->r_info);

                    int rc = parse_reloc(secidx, relidx, symshdr, dstshdr, r_offset, symoffset, type, 0);
                    if (rc)
                        return rc;
                }
            }

            else if (shdr->sh_type == SHT_RELA) {
                Elf_Rela *rela;
                int relidx = -1;
                elf_for_every_relocation(buf, shdr, rela) {
                    relidx++;
                    Elf_Addr r_offset = rela->r_offset;
                    Elf_Addr symoffset = ELF_R_SYM(rela->r_info);
                    Elf_Xword type = ELF_R_TYPE(rela->r_info);
                    Elf_Sxword r_addend =  rela->r_addend;

                    int rc = parse_reloc(secidx, relidx, symshdr, dstshdr, r_offset, symoffset, type, r_addend);
                    if (rc)
                        return rc;
                }
            }
        }

        if (g_machine == EM_ARM) {
            // GCC doesn't emit relocations for these so generate them ourselves
            elf_for_every_section(buf, ehdr, shdr) {
                if (shdr->sh_type == SHT_SYMTAB) {
                    Elf_Sym *symtab = (Elf_Sym*)(buf + shdr->sh_offset);

                    Elf_Sym *sym;
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
        }
    }

    else if (ehdr->e_type == ET_DYN) {
        if (!dyn) {
            fprintf(stderr, "dynamic section not found\n");
            return -1;
        }

        size_t i;
        Elf_Xword dt_relsz = 0;
        Elf_Xword dt_relent = 0;
        Elf_Rel *dt_rel = 0;
        Elf_Xword dt_relasz = 0;
        Elf_Xword dt_relaent = 0;
        Elf_Rela *dt_rela = 0;
        for (i=0; dyn[i].d_tag!=DT_NULL; i++) {
            switch (dyn[i].d_tag) {
                case DT_REL:
                    dt_rel = (((void*)g_ehdr) + dyn[i].d_un.d_ptr);
                    break;

                case DT_RELSZ:
                    dt_relsz = dyn[i].d_un.d_val;
                    break;

                case DT_RELENT:
                    dt_relent = dyn[i].d_un.d_val;
                    break;

                case DT_RELA:
                    dt_rela = (((void*)g_ehdr) + dyn[i].d_un.d_ptr);
                    break;

                case DT_RELASZ:
                    dt_relasz = dyn[i].d_un.d_val;
                    break;

                case DT_RELAENT:
                    dt_relaent = dyn[i].d_un.d_val;
                    break;

                default:
                    break;
            }
        }

        if (dt_rel && dt_relsz && dt_relent) {
            Elf_Rel *rel;
            int relidx = -1;
            elf_for_every_relocation_dt(dt_rel, dt_relsz, dt_relent, rel) {
                relidx++;
                Elf_Addr r_offset = rel->r_offset;
                Elf_Addr symoffset = ELF_R_SYM(rel->r_info);
                Elf_Xword type = ELF_R_TYPE(rel->r_info);

                int rc = parse_reloc(-1, relidx, NULL, NULL, r_offset, symoffset, type, 0);
                if (rc)
                    return rc;
            }
        }

        if (dt_rela && dt_relasz && dt_relaent) {
            Elf_Rela *rela;
            int relidx = -1;
            elf_for_every_relocation_dt(dt_rela, dt_relasz, dt_relaent, rela) {
                relidx++;
                Elf_Addr r_offset = rela->r_offset;
                Elf_Addr symoffset = ELF_R_SYM(rela->r_info);
                Elf_Xword type = ELF_R_TYPE(rela->r_info);
                Elf_Sxword r_addend =  rela->r_addend;

                int rc = parse_reloc(-1, relidx, NULL, NULL, r_offset, symoffset, type, r_addend);
                if (rc)
                    return rc;
            }
        }
    }

    else {
        fprintf(stderr, "invalid elf type\n");
        return -1;
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

    off_t table_offset = sizeof(EFI_IMAGE_DOS_HEADER) + 0x40 + sizeof (EFI_IMAGE_NT_HEADERS);
    size_t table_size = 3 * sizeof(EFI_IMAGE_SECTION_HEADER);

    Elf_Addr text_address = MAX(coff_align(table_offset + table_size), coff_alignment);
    off_t loading_offset = text_address - phdr_text->p_vaddr;

    Elf_Addr data_addr_real = phdr_data->p_vaddr + loading_offset;
    Elf_Addr data_addr_rounded = ROUNDDOWN(data_addr_real, coff_alignment);
    Elf_Addr data_addr_diff = data_addr_real - data_addr_rounded;

    memset(&secHdrText, 0, sizeof(secHdrText));
    strcpy((char *)secHdrText.Name, ".text");
    secHdrText.Misc.VirtualSize = coff_align(phdr_text->p_memsz);
    secHdrText.VirtualAddress = phdr_text->p_vaddr + loading_offset;
    secHdrText.SizeOfRawData = coff_align(phdr_text->p_memsz);
    secHdrText.PointerToRawData = secHdrText.VirtualAddress;
    secHdrText.Characteristics = EFI_IMAGE_SCN_CNT_CODE
            | EFI_IMAGE_SCN_MEM_EXECUTE
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

    size_t selfreloc_size = sizeof(efi_relocation_hdr_t) + elochdr.num_relocs * sizeof(efi_relocation_t);

    memset(&secHdrESR, 0, sizeof(secHdrESR));
    strcpy((char *)secHdrESR.Name, "esr");
    secHdrESR.Misc.VirtualSize = coff_align(selfreloc_size);
    secHdrESR.VirtualAddress = secHdrData.VirtualAddress + secHdrData.Misc.VirtualSize;
    secHdrESR.SizeOfRawData = coff_align(selfreloc_size);
    secHdrESR.PointerToRawData = secHdrESR.VirtualAddress;
    secHdrESR.Characteristics = EFI_IMAGE_SCN_CNT_INITIALIZED_DATA
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
    ntHdr.Pe32Arch.Signature = EFI_IMAGE_NT_SIGNATURE;
    if (g_machine==EM_ARM)
        ntHdr.Pe32Arch.FileHeader.Machine = EFI_IMAGE_MACHINE_ARMT;
    else if (g_machine==EM_X86_64)
        ntHdr.Pe32Arch.FileHeader.Machine = IMAGE_FILE_MACHINE_X64;
    ntHdr.Pe32Arch.OptionalHeader.Magic = EFI_IMAGE_NT_OPTIONAL_HDR_MAGIC;

    ntHdr.Pe32Arch.FileHeader.NumberOfSections = 3;
    ntHdr.Pe32Arch.FileHeader.TimeDateStamp = 0;
    ntHdr.Pe32Arch.FileHeader.PointerToSymbolTable = 0;
    ntHdr.Pe32Arch.FileHeader.NumberOfSymbols = 0;
    ntHdr.Pe32Arch.FileHeader.SizeOfOptionalHeader = sizeof(ntHdr.Pe32Arch.OptionalHeader);
    ntHdr.Pe32Arch.FileHeader.Characteristics = EFI_IMAGE_FILE_EXECUTABLE_IMAGE
      | EFI_IMAGE_FILE_LINE_NUMS_STRIPPED
      | EFI_IMAGE_FILE_LOCAL_SYMS_STRIPPED;

#if ELF2EFI_BITS == 32
    ntHdr.Pe32Arch.FileHeader.Characteristics |= EFI_IMAGE_FILE_32BIT_MACHINE;
#elif ELF2EFI_BITS == 64
    ntHdr.Pe32Arch.FileHeader.Characteristics |= EFI_IMAGE_FILE_LARGE_ADDRESS_AWARE;
#endif

    ntHdr.Pe32Arch.OptionalHeader.SizeOfCode = secHdrText.Misc.VirtualSize;
    ntHdr.Pe32Arch.OptionalHeader.SizeOfInitializedData = secHdrData.Misc.VirtualSize;
    ntHdr.Pe32Arch.OptionalHeader.SizeOfUninitializedData = 0;
    ntHdr.Pe32Arch.OptionalHeader.AddressOfEntryPoint = g_ehdr->e_entry + loading_offset;

    ntHdr.Pe32Arch.OptionalHeader.BaseOfCode = secHdrText.VirtualAddress;

#if ELF2EFI_BITS == 32
    ntHdr.Pe32.OptionalHeader.BaseOfData = secHdrData.VirtualAddress;
#endif
    ntHdr.Pe32Arch.OptionalHeader.ImageBase = 0;
    ntHdr.Pe32Arch.OptionalHeader.SectionAlignment = coff_alignment;
    ntHdr.Pe32Arch.OptionalHeader.FileAlignment = coff_alignment;
    ntHdr.Pe32Arch.OptionalHeader.SizeOfImage = coff_align(secHdrESR.VirtualAddress + secHdrESR.SizeOfRawData);
    ntHdr.Pe32Arch.OptionalHeader.Subsystem = EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION;

    ntHdr.Pe32Arch.OptionalHeader.SizeOfHeaders = secHdrText.PointerToRawData;
    ntHdr.Pe32Arch.OptionalHeader.NumberOfRvaAndSizes = EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;

    lseek(fd, 0x40, SEEK_CUR);
    write(fd, &ntHdr, sizeof(ntHdr));

    // section headers
    lseek(fd, table_offset, SEEK_SET);
    write(fd, &secHdrText, sizeof(secHdrText));
    write(fd, &secHdrData, sizeof(secHdrData));
    write(fd, &secHdrESR, sizeof(secHdrESR));

    // .text
    lseek(fd, secHdrText.PointerToRawData, SEEK_SET);
    write(fd, ((void*)g_ehdr) + phdr_text->p_offset, phdr_text->p_filesz);

    // .data
    lseek(fd, secHdrData.PointerToRawData + data_addr_diff, SEEK_SET);
    write(fd, ((void*)g_ehdr) + phdr_data->p_offset, phdr_data->p_filesz);

    // esr
    elochdr.text_base = phdr_text->p_vaddr;
    elochdr.text_size = secHdrText.Misc.VirtualSize;
    elochdr.elf_type = g_ehdr->e_type;

    lseek(fd, secHdrESR.PointerToRawData, SEEK_SET);
    write(fd, &elochdr, sizeof(efi_relocation_hdr_t));
    write(fd, efirelocs, elochdr.num_relocs * sizeof(efi_relocation_t));

    ftruncate(fd, ntHdr.Pe32Arch.OptionalHeader.SizeOfImage);
    close(fd);

    return 0;
}

int FN(do_convert)(void *buf, size_t bufsz, const char *filename_efi) {
    int rc;

    memset(&elochdr, 0, sizeof(elochdr));

    rc = parse_elf(buf, bufsz);
    if (rc) {
        fprintf(stderr, "Can't parse elf\n");
        return -1;
    }

    rc = write_efi(filename_efi);
    if (rc) {
        fprintf(stderr, "Can't write efi\n");
        return -1;
    }

    return rc;
}
