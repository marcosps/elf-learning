/* These definitions were taken from elf.h */

/* Special section indexes. */
#define SHN_UNDEF	0 /* undefined section */
#define SHN_ABS		0xfff1 /* Associated symbol is absolute */
#define SHN_LOOS	0xff20 /* Start index of OS specific sections */
#define SHN_HIOS	0xff3f /* End index of OS specific sections */

/* AMD x86-64 relocations. */
#define R_X86_64_NONE		0	/* No reloc */
#define R_X86_64_64		1	/* Direct 64 bit  */
#define R_X86_64_PC32		2	/* PC relative 32 bit signed */
#define R_X86_64_GOT32		3	/* 32 bit GOT entry */
#define R_X86_64_PLT32		4	/* 32 bit PLT address */
#define R_X86_64_COPY		5	/* Copy symbol at runtime */
#define R_X86_64_GLOB_DAT	6	/* Create GOT entry */
#define R_X86_64_JUMP_SLOT	7	/* Create PLT entry */
#define R_X86_64_RELATIVE	8	/* Adjust by program base */
#define R_X86_64_GOTPCREL	9	/* 32 bit signed PC relative
					   offset to GOT */
#define R_X86_64_32		10	/* Direct 32 bit zero extended */
#define R_X86_64_32S		11	/* Direct 32 bit sign extended */
#define R_X86_64_16		12	/* Direct 16 bit zero extended */
#define R_X86_64_PC16		13	/* 16 bit sign extended pc relative */
#define R_X86_64_8		14	/* Direct 8 bit sign extended  */
#define R_X86_64_PC8		15	/* 8 bit sign extended pc relative */
#define R_X86_64_DTPMOD64	16	/* ID of module containing symbol */
#define R_X86_64_DTPOFF64	17	/* Offset in module's TLS block */
#define R_X86_64_TPOFF64	18	/* Offset in initial TLS block */
#define R_X86_64_TLSGD		19	/* 32 bit signed PC relative offset
					   to two GOT entries for GD symbol */
#define R_X86_64_TLSLD		20	/* 32 bit signed PC relative offset
					   to two GOT entries for LD symbol */
#define R_X86_64_DTPOFF32	21	/* Offset in TLS block */
#define R_X86_64_GOTTPOFF	22	/* 32 bit signed PC relative offset
					   to GOT entry for IE symbol */
#define R_X86_64_TPOFF32	23	/* Offset in initial TLS block */
#define R_X86_64_PC64		24	/* PC relative 64 bit */
#define R_X86_64_GOTOFF64	25	/* 64 bit offset to GOT */
#define R_X86_64_GOTPC32	26	/* 32 bit signed pc relative
					   offset to GOT */
#define R_X86_64_GOT64		27	/* 64-bit GOT entry offset */
#define R_X86_64_GOTPCREL64	28	/* 64-bit PC relative offset
					   to GOT entry */
#define R_X86_64_GOTPC64	29	/* 64-bit PC relative offset to GOT */
#define R_X86_64_GOTPLT64	30 	/* like GOT64, says PLT entry needed */
#define R_X86_64_PLTOFF64	31	/* 64-bit GOT relative offset
					   to PLT entry */
#define R_X86_64_SIZE32		32	/* Size of symbol plus 32-bit addend */
#define R_X86_64_SIZE64		33	/* Size of symbol plus 64-bit addend */
#define R_X86_64_GOTPC32_TLSDESC 34	/* GOT offset for TLS descriptor.  */
#define R_X86_64_TLSDESC_CALL   35	/* Marker for call through TLS
					   descriptor.  */
#define R_X86_64_TLSDESC        36	/* TLS descriptor.  */
#define R_X86_64_IRELATIVE	37	/* Adjust indirectly by program base */
#define R_X86_64_RELATIVE64	38	/* 64-bit adjust by program base */
					/* 39 Reserved was R_X86_64_PC32_BND */
					/* 40 Reserved was R_X86_64_PLT32_BND */
#define R_X86_64_GOTPCRELX	41	/* Load from 32 bit signed pc relative
					   offset to GOT entry without REX
					   prefix, relaxable.  */
#define R_X86_64_REX_GOTPCRELX	42	/* Load from 32 bit signed pc relative
					   offset to GOT entry with REX prefix,
					   relaxable.  */
#define R_X86_64_NUM		43

/* x86-64 sh_type values.  */
#define SHT_X86_64_UNWIND	0x70000001 /* Unwind information.  */

/* Legal values for sh_flags (section flags).  */

#define SHF_WRITE	     (1 << 0)	/* Writable */
#define SHF_ALLOC	     (1 << 1)	/* Occupies memory during execution */
#define SHF_EXECINSTR	     (1 << 2)	/* Executable */
#define SHF_MERGE	     (1 << 4)	/* Might be merged */
#define SHF_STRINGS	     (1 << 5)	/* Contains nul-terminated strings */
#define SHF_INFO_LINK	     (1 << 6)	/* `sh_info' contains SHT index */
#define SHF_LINK_ORDER	     (1 << 7)	/* Preserve order after combining */
#define SHF_OS_NONCONFORMING (1 << 8)	/* Non-standard OS specific handling
					   required */
#define SHF_GROUP	     (1 << 9)	/* Section is member of a group.  */
#define SHF_TLS		     (1 << 10)	/* Section hold thread-local data.  */
#define SHF_COMPRESSED	     (1 << 11)	/* Section with compressed data. */
#define SHF_MASKOS	     0x0ff00000	/* OS-specific.  */
#define SHF_MASKPROC	     0xf0000000	/* Processor-specific */
#define SHF_GNU_RETAIN	     (1 << 21)  /* Not to be GCed by linker.  */
#define SHF_ORDERED	     (1 << 30)	/* Special ordering requirement
					   (Solaris).  */
#define SHF_EXCLUDE	     (1U << 31)	/* Section is excluded unless
					   referenced or allocated (Solaris).*/

/* Legal values for ST_TYPE subfield of st_info (symbol type).  */

#define STT_NOTYPE	0		/* Symbol type is unspecified */
#define STT_OBJECT	1		/* Symbol is a data object */
#define STT_FUNC	2		/* Symbol is a code object */
#define STT_SECTION	3		/* Symbol associated with a section */
#define STT_FILE	4		/* Symbol's name is file name */
#define STT_COMMON	5		/* Symbol is a common data object */
#define STT_TLS		6		/* Symbol is thread-local data object*/
#define	STT_NUM		7		/* Number of defined types.  */
#define STT_LOOS	10		/* Start of OS-specific */
#define STT_GNU_IFUNC	10		/* Symbol is indirect code object */
#define STT_HIOS	12		/* End of OS-specific */
#define STT_LOPROC	13		/* Start of processor-specific */
#define STT_HIPROC	15		/* End of processor-specific */

/* Legal values for ST_BIND subfield of st_info (symbol binding).  */

#define STB_LOCAL	0		/* Local symbol */
#define STB_GLOBAL	1		/* Global symbol */
#define STB_WEAK	2		/* Weak symbol */
#define	STB_NUM		3		/* Number of defined types.  */
#define STB_LOOS	10		/* Start of OS-specific */
#define STB_GNU_UNIQUE	10		/* Unique symbol.  */
#define STB_HIOS	12		/* End of OS-specific */
#define STB_LOPROC	13		/* Start of processor-specific */
#define STB_HIPROC	15		/* End of processor-specific */

/* Symbol visibility specification encoded in the st_other field.  */
#define STV_DEFAULT	0		/* Default symbol visibility rules */
#define STV_INTERNAL	1		/* Processor specific hidden class */
#define STV_HIDDEN	2		/* Sym unavailable in other modules */
#define STV_PROTECTED	3		/* Not preemptible, not exported */

/* Legal values for e_type (object file type).  */

#define ET_NONE		0		/* No file type */
#define ET_REL		1		/* Relocatable file */
#define ET_EXEC		2		/* Executable file */
#define ET_DYN		3		/* Shared object file */
#define ET_CORE		4		/* Core file */
#define	ET_NUM		5		/* Number of defined types */
#define ET_LOOS		0xfe00		/* OS-specific range start */
#define ET_HIOS		0xfeff		/* OS-specific range end */
#define ET_LOPROC	0xff00		/* Processor-specific range start */
#define ET_HIPROC	0xffff		/* Processor-specific range end */

#define SHT_NULL	  0		/* Section header table entry unused */
#define SHT_PROGBITS	  1		/* Program data */
#define SHT_SYMTAB	  2		/* Symbol table */
#define SHT_STRTAB	  3		/* String table */
#define SHT_RELA	  4		/* Relocation entries with addends */
#define SHT_HASH	  5		/* Symbol hash table */
#define SHT_DYNAMIC	  6		/* Dynamic linking information */
#define SHT_NOTE	  7		/* Notes */
#define SHT_NOBITS	  8		/* Program space with no data (bss) */
#define SHT_REL		  9		/* Relocation entries, no addends */
#define SHT_SHLIB	  10		/* Reserved */
#define SHT_DYNSYM	  11		/* Dynamic linker symbol table */
#define SHT_INIT_ARRAY	  14		/* Array of constructors */
#define SHT_FINI_ARRAY	  15		/* Array of destructors */
#define SHT_PREINIT_ARRAY 16		/* Array of pre-constructors */
#define SHT_GROUP	  17		/* Section group */
#define SHT_SYMTAB_SHNDX  18		/* Extended section indices */
#define SHT_RELR	  19            /* RELR relative relocations */
#define	SHT_NUM		  20		/* Number of defined types.  */
#define SHT_LOOS	  0x60000000	/* Start OS-specific.  */
#define SHT_GNU_ATTRIBUTES 0x6ffffff5	/* Object attributes.  */
#define SHT_GNU_HASH	  0x6ffffff6	/* GNU-style hash table.  */
#define SHT_GNU_LIBLIST	  0x6ffffff7	/* Prelink library list */
#define SHT_CHECKSUM	  0x6ffffff8	/* Checksum for DSO content.  */
#define SHT_LOSUNW	  0x6ffffffa	/* Sun-specific low bound.  */
#define SHT_SUNW_move	  0x6ffffffa
#define SHT_SUNW_COMDAT   0x6ffffffb
#define SHT_SUNW_syminfo  0x6ffffffc
#define SHT_GNU_verdef	  0x6ffffffd	/* Version definition section.  */
#define SHT_GNU_verneed	  0x6ffffffe	/* Version needs section.  */
#define SHT_GNU_versym	  0x6fffffff	/* Version symbol table.  */
#define SHT_HISUNW	  0x6fffffff	/* Sun-specific high bound.  */
#define SHT_HIOS	  0x6fffffff	/* End OS-specific type */
#define SHT_LOPROC	  0x70000000	/* Start of processor-specific */
#define SHT_HIPROC	  0x7fffffff	/* End of processor-specific */
#define SHT_LOUSER	  0x80000000	/* Start of application-specific */
#define SHT_HIUSER	  0x8fffffff	/* End of application-specific */

/* Legal values for p_type (segment type).  */

#define	PT_NULL		0		/* Program header table entry unused */
#define PT_LOAD		1		/* Loadable program segment */
#define PT_DYNAMIC	2		/* Dynamic linking information */
#define PT_INTERP	3		/* Program interpreter */
#define PT_NOTE		4		/* Auxiliary information */
#define PT_SHLIB	5		/* Reserved */
#define PT_PHDR		6		/* Entry for header table itself */
#define PT_TLS		7		/* Thread-local storage segment */
#define	PT_NUM		8		/* Number of defined types */
#define PT_LOOS		0x60000000	/* Start of OS-specific */
#define PT_GNU_EH_FRAME	0x6474e550	/* GCC .eh_frame_hdr segment */
#define PT_GNU_STACK	0x6474e551	/* Indicates stack executability */
#define PT_GNU_RELRO	0x6474e552	/* Read-only after relocation */
#define PT_GNU_PROPERTY	0x6474e553	/* GNU property */
#define PT_LOSUNW	0x6ffffffa
#define PT_SUNWBSS	0x6ffffffa	/* Sun Specific segment */
#define PT_SUNWSTACK	0x6ffffffb	/* Stack segment */
#define PT_HISUNW	0x6fffffff
#define PT_HIOS		0x6fffffff	/* End of OS-specific */
#define PT_LOPROC	0x70000000	/* Start of processor-specific */
#define PT_HIPROC	0x7fffffff	/* End of processor-specific */

#define EI_NIDENT 16

// Copied from linux/elf.h
#define SHN_LIVEPATCH   0xff20

struct elf_header {
	unsigned char e_ident[EI_NIDENT];
	int e_type;
	int e_machine;
	int e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	int e_flags;
	int e_ehsize;
	int e_phentsize;
	int e_phnum;
	int e_shentsize;
	int e_shnum;
	int e_shstrndx;
};

struct sh_entry {
	int sh_name;
	uint64_t sh_type;
	int sh_flags;
	int sh_addr;
	int sh_offset;
	int sh_size;
	int sh_link;
	int sh_info;
	int sh_addralign;
	int sh_entsize;
};

struct ph_entry {
	int p_type;
	int p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

struct sym_entry_64 {
	uint32_t st_name;
	unsigned char st_info;
	unsigned char st_other;
	uint16_t st_shndx;
	uint64_t st_value;
	uint64_t st_size;
};

struct sym_entry_32 {
	uint32_t st_name;
	uint32_t st_value;
	uint32_t st_size;
	unsigned char st_info;
	unsigned char st_other;
	uint16_t st_shndx;
};

/* There are only two symbol tables in ELF files: symtab and dyntab */
enum SymbleTables {
	SYMTAB,
	DYNTAB,
};

struct sym_tab {
	int sh_entry;
	char *desc;
	unsigned int tab_off;
	unsigned int tab_len;
	unsigned int entry_size;
	unsigned int strtab_off;
	unsigned int strtab_len;
	unsigned int nentries;
	struct sym_entry_64 entries[] __attribute__((counted_by(nentries)));
};

struct rela_entry {
	uint64_t r_offset;
	uint64_t r_info;
	int64_t r_addend;
};

enum patch_sections {
	MCOUNT_LOC,
	PATCHABLE_FUNCTION_ENTRIES,
};

char *patch_tabs[] = {
	"__mcount_loc" ,
	"__patchable_function_entries",
};

struct patchable_funcs {
	int type;
	unsigned long offset;
	unsigned int len;
};

/*
 * Join prefix with val, and stringify val. E.g.
 * case SHT_NULL: return "NULL";
 **/
#define CHECK_VAL(opt, val) case opt: return #val;
#define CASEPTYPE(val) CHECK_VAL(PT_ ## val, val)
static char *get_ph_type(int type)
{
	switch (type) {
	CASEPTYPE(NULL);
	CASEPTYPE(LOAD);
	CASEPTYPE(DYNAMIC);
	CASEPTYPE(INTERP);
	CASEPTYPE(NOTE);
	CASEPTYPE(SHLIB);
	CASEPTYPE(PHDR);
	CASEPTYPE(TLS);
	CASEPTYPE(LOOS);
	CASEPTYPE(GNU_EH_FRAME);
	CASEPTYPE(GNU_STACK);
	CASEPTYPE(GNU_RELRO);
	CASEPTYPE(GNU_PROPERTY);
	CASEPTYPE(HIOS);
	CASEPTYPE(LOPROC);
	CASEPTYPE(HIPROC);
	default:
		return "UNKNOWN";
	}
}

#define CASESTYPE(val) CHECK_VAL(SHT_ ## val, val)
static char *get_sh_type(uint64_t type)
{
	switch (type) {
	CASESTYPE(NULL);
	CASESTYPE(PROGBITS);
	CASESTYPE(SYMTAB);
	CASESTYPE(STRTAB);
	CASESTYPE(RELA);
	CASESTYPE(HASH);
	CASESTYPE(DYNAMIC);
	CASESTYPE(NOTE);
	CASESTYPE(NOBITS);
	CASESTYPE(REL);
	CASESTYPE(SHLIB);
	CASESTYPE(DYNSYM);
	CASESTYPE(INIT_ARRAY);
	CASESTYPE(FINI_ARRAY);
	CASESTYPE(PREINIT_ARRAY);
	CASESTYPE(GROUP);
	CASESTYPE(SYMTAB_SHNDX);
	CASESTYPE(NUM);
	CASESTYPE(LOOS);
	CASESTYPE(GNU_ATTRIBUTES);
	CASESTYPE(GNU_HASH);
	CASESTYPE(GNU_LIBLIST);
	CASESTYPE(CHECKSUM);
	CASESTYPE(GNU_verdef);
	CASESTYPE(GNU_verneed);
	CASESTYPE(GNU_versym);
	CASESTYPE(LOPROC);
	CASESTYPE(HIPROC);
	CASESTYPE(LOUSER);
	CASESTYPE(HIUSER);
	default:
		return "UNKNOWN";
	}
}

#define SYMT(val) CHECK_VAL(STT_ ## val, val)
static char *get_symbol_type(unsigned char st_info)
{
	unsigned char val = st_info & 0xf;
	switch (val) {
	SYMT(NOTYPE);
	SYMT(OBJECT);
	SYMT(FUNC);
	SYMT(SECTION);
	SYMT(FILE);
	SYMT(COMMON);
	SYMT(TLS);
	SYMT(NUM);
	SYMT(GNU_IFUNC);
	default:
		return "UNKNOWN";
	}
}

#define SYMB(val) CHECK_VAL(STB_ ## val, val)
static char *get_symbol_bind(unsigned char info)
{
	unsigned char val = info >> 4;
	switch (val) {
	SYMB(LOCAL);
	SYMB(GLOBAL);
	SYMB(WEAK);
	SYMB(NUM);
	SYMB(LOOS);
	SYMB(HIOS);
	SYMB(LOPROC);
	SYMB(HIPROC);
	default:
		return "UNKNOWN";
	}
}

#define SYMV(val) CHECK_VAL(STV_ ## val, val)
static char *get_symbol_visibility(unsigned char val)
{
	switch (val) {
	SYMV(DEFAULT);
	SYMV(INTERNAL);
	SYMV(HIDDEN);
	SYMV(PROTECTED);
	default:
		return "UNKNOWN";
	}
}

#define OBJT(val, str) case ET_ ## val: return str
static char *get_object_type(int val)
{
	switch (val) {
	OBJT(NONE, "NONE");
	OBJT(REL, "REL (Relocatable file)");
	OBJT(EXEC, "EXEC (Executable file)");
	OBJT(DYN, "DYN (Shared object file)");
	OBJT(CORE, "CORE (Core File)");
	OBJT(NUM, "NUM (nr defined types");
	default:
		return "UNKNOWN";
	}
}

#define SHF_FLAG(val, ch) if (flags & val) flag_buf[pos++] = ch;
static void get_section_flag(uint64_t flags, char *flag_buf)
{
	int pos = 0;

	SHF_FLAG(SHF_WRITE, 'W');
	SHF_FLAG(SHF_ALLOC, 'A');
	SHF_FLAG(SHF_EXECINSTR, 'E');
	SHF_FLAG(SHF_MERGE, 'M');
	SHF_FLAG(SHF_STRINGS, 'S');
	SHF_FLAG(SHF_INFO_LINK, 'I');
	SHF_FLAG(SHF_LINK_ORDER, 'L');
	SHF_FLAG(SHF_OS_NONCONFORMING, 'O');
	SHF_FLAG(SHF_GROUP, 'G');
	SHF_FLAG(SHF_TLS, 'T');
	SHF_FLAG(SHF_MASKOS, 'o'); /* same flag used by readelf */
	SHF_FLAG(SHF_MASKPROC, '?'); //FIXME
	SHF_FLAG(SHF_ORDERED, 'O');
	SHF_FLAG(SHF_EXCLUDE, 'E');
}

#define REL_TYPE(val) case val: return #val; break;
static char *get_rel_type(uint64_t r_info)
{
	switch (r_info) {
	REL_TYPE(R_X86_64_NONE)
	REL_TYPE(R_X86_64_64)
	REL_TYPE(R_X86_64_PC32)
	REL_TYPE(R_X86_64_GOT32)
	REL_TYPE(R_X86_64_PLT32)
	REL_TYPE(R_X86_64_COPY)
	REL_TYPE(R_X86_64_GLOB_DAT)
	REL_TYPE(R_X86_64_JUMP_SLOT)
	REL_TYPE(R_X86_64_RELATIVE)
	REL_TYPE(R_X86_64_GOTPCREL)
	REL_TYPE(R_X86_64_32)
	REL_TYPE(R_X86_64_32S)
	REL_TYPE(R_X86_64_16)
	REL_TYPE(R_X86_64_PC16)
	REL_TYPE(R_X86_64_8)
	REL_TYPE(R_X86_64_PC8)
	REL_TYPE(R_X86_64_DTPMOD64)
	REL_TYPE(R_X86_64_DTPOFF64)
	REL_TYPE(R_X86_64_TPOFF64)
	REL_TYPE(R_X86_64_TLSGD)
	REL_TYPE(R_X86_64_TLSLD)
	REL_TYPE(R_X86_64_DTPOFF32)
	REL_TYPE(R_X86_64_GOTTPOFF)
	REL_TYPE(R_X86_64_TPOFF32)
	REL_TYPE(R_X86_64_PC64)
	REL_TYPE(R_X86_64_GOTOFF64)
	REL_TYPE(R_X86_64_GOTPC32)
	REL_TYPE(R_X86_64_GOT64)
	REL_TYPE(R_X86_64_GOTPCREL64)
	REL_TYPE(R_X86_64_GOTPC64)
	REL_TYPE(R_X86_64_GOTPLT64)
	REL_TYPE(R_X86_64_PLTOFF64)
	REL_TYPE(R_X86_64_SIZE32)
	REL_TYPE(R_X86_64_SIZE64)
	REL_TYPE(R_X86_64_GOTPC32_TLSDESC)
	REL_TYPE(R_X86_64_TLSDESC_CALL)
	REL_TYPE(R_X86_64_TLSDESC)
	REL_TYPE(R_X86_64_IRELATIVE)
	REL_TYPE(R_X86_64_RELATIVE64)
	REL_TYPE(R_X86_64_GOTPCRELX)
	REL_TYPE(R_X86_64_REX_GOTPCRELX)
	REL_TYPE(R_X86_64_NUM)
	default:
		return "missing rel_type...";
	}
}
