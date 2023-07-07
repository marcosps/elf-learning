#include <err.h>
#include <fcntl.h>
#include <stdbool.h> // bool
#include <stdio.h>
#include <stdlib.h> // malloc
#include <string.h> // memcpy
#include <inttypes.h> //uint64_t
#include <sys/mman.h> // mmap
#include <sys/stat.h> //fstat
#include <unistd.h> //close

#include "elf-defs.h"

static unsigned char *mfile;

static bool is64bit = false;
/* Some fields use 8 bytes when in 64bit ELF files */
static char nbytes;

static unsigned int modinfo_off;
static unsigned int modinfo_len;

#define EI_NIDENT 16

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

static struct elf_header eh;

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

static struct sh_entry *sh_entries = NULL;

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

static struct ph_entry *ph_entries = NULL;

struct sym_entry {
	uint32_t st_name;
	unsigned char st_info;
	unsigned char st_other;
	uint16_t st_shndx;
	uint64_t st_value;
	uint64_t st_size;
};

/* There are only two symbol tables in ELF files: symtab and dyntab */
#define SYMTAB 0
#define DYNTAB 1

static struct sym_tab {
	unsigned int tab_off;
	unsigned int tab_len;
	unsigned int entry_size;
	unsigned int strtab_off;
	unsigned int strtab_len;
	unsigned int nentries;
	struct sym_entry *entries;
} tabs[2] = {};

struct rela_entry {
	uint64_t r_offset;
	uint64_t r_info;
	int64_t r_addend;
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
static char *get_symbol_type(struct sym_entry *sym)
{
	unsigned char val = sym->st_info & 0xf;
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

/* Get value mfile starting from offset + len */
static uint64_t get_field(size_t *offset, size_t len)
{
	unsigned char data[9] = {0};

	memcpy(data, mfile + *offset, len);

	*offset += len;

	/* Big enough to store 32 and 64 bit values */
	return *(uint64_t *)data;
}

static void get_eh_fields()
{
	size_t pos = 16;

	if (mfile[0] != 0x7f)
		errx(1, "Not an ELF file");

	if (mfile[4] == 2)
		is64bit = true;

	eh.e_type = get_field(&pos, 2);
	eh.e_machine = get_field(&pos, 2);
	eh.e_version = get_field(&pos, 4);

	/* The number of bytes of some fields in the Elf Header. */
	nbytes = is64bit ? 8 : 4;

	eh.e_entry = get_field(&pos, nbytes);
	eh.e_phoff = get_field(&pos, nbytes);
	eh.e_shoff = get_field(&pos, nbytes);
	eh.e_flags = get_field(&pos, 4);
	eh.e_ehsize = get_field(&pos, 2);
	eh.e_phentsize = get_field(&pos, 2);
	eh.e_phnum = get_field(&pos, 2);
	eh.e_shentsize = get_field(&pos, 2);
	eh.e_shnum = get_field(&pos, 2);
	eh.e_shstrndx = get_field(&pos, 2);

	printf("ELF Header\n");
	printf("  Magic numbers: %#0x - %c%c%c\n", mfile[0], mfile[1], mfile[2], mfile[3]);
	printf("  The ELF file was compiled for %s endian machines\n", mfile[5] == 1 ? "little" : "big");
	printf("  OS ABI: 0x%d (0 == System V)\n", mfile[7]);

	printf("  Object type: %s\n", get_object_type(eh.e_type));
	printf("  ISA: 0x%x\n", eh.e_machine);
	printf("  ELF version: %d\n", eh.e_version);
	printf("  Entry point: 0x%lx\n", eh.e_entry);
	printf("  Program header offset (bytes): %lu\n", eh.e_phoff);
	printf("  Section header offset (bytes): %lu\n", eh.e_shoff);
	printf("  Flags: 0x%x\n", eh.e_flags);
	printf("  Size of this header (bytes): %d\n", eh.e_ehsize);
	printf("  Size of program header (bytes): %d\n", eh.e_phentsize);
	printf("  Number of program headers: %d\n", eh.e_phnum);
	printf("  Size of section headers (bytes): %d\n", eh.e_shentsize);
	printf("  Number of section headers: %d\n", eh.e_shnum);
	printf("  Section header string table index: %d\n", eh.e_shstrndx);
}

static void get_prog_flags(uint64_t flags, char *flag_buf)
{
	flag_buf[0] = flags & 0x4 ? 'R' : ' ';
	flag_buf[1] = flags & 0x2 ? 'W' : ' ';
	flag_buf[2] = flags & 0x1 ? 'E' : ' ';
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

static void get_program_header(size_t ph_index, struct ph_entry *entry)
{
	size_t pos = eh.e_phoff + (ph_index * eh.e_phentsize);

	/* Type is 4 bytes both in 32 and 64 bit */
	entry->p_type = get_field(&pos, 4);

	/* On 64 bit, the flags field comes after the type */
	if (is64bit)
		entry->p_flags = get_field(&pos, 4);

	entry->p_offset = get_field(&pos, nbytes);
	entry->p_vaddr = get_field(&pos, nbytes);
	entry->p_paddr = get_field(&pos, nbytes);
	entry->p_filesz = get_field(&pos, nbytes);
	entry->p_memsz = get_field(&pos, nbytes);

	/* On 32bit, the flag field exists after the MemSize */
	if (!is64bit)
		entry->p_flags = get_field(&pos, 4);

	entry->p_align = get_field(&pos, nbytes);
}

static void show_program_headers()
{
	int i;
	struct ph_entry *entry;

	/* Return if the file does not contain a program header table */
	if (eh.e_phoff == 0)
		return;

	for (i = 0; i < eh.e_phnum; i++) {
		entry = &ph_entries[i];

		get_program_header(i, entry);

		/* Get interp info */
		if (entry->p_type == 3)
			printf("  Interpreter: %s\n", mfile + entry->p_offset);
	}

	printf("\nProgram Headers:\n");
	printf("  Type             Offset               VirtAddr             PhysAddr\n"
	       "                   FileSiz              MemSiz                 Flags   Align\n");
	for (i = 0; i < eh.e_phnum; i++) {
		char flag_buf[4] = {};

		entry = &ph_entries[i];
		get_prog_flags(entry->p_flags, flag_buf);
		printf("  %-14s   0x%016lx   0x%016lx   0x%016lx\n"
		       "                   0x%016lx   0x%016lx     %-5s   0x%lx\n",
				get_ph_type(entry->p_type),
				entry->p_offset,
				entry->p_vaddr,
				entry->p_paddr,

				entry->p_filesz,
				entry->p_memsz,
				flag_buf,
				entry->p_align);
	}

	printf("\n");
}

static void get_section_header(size_t sh_index, struct sh_entry *entry)
{
	size_t pos = eh.e_shoff + (sh_index * eh.e_shentsize);

	entry->sh_name = get_field(&pos, 4);
	entry->sh_type = get_field(&pos, 4);
	entry->sh_flags = get_field(&pos, nbytes);
	entry->sh_addr = get_field(&pos, nbytes);
	entry->sh_offset = get_field(&pos, nbytes);
	entry->sh_size = get_field(&pos, nbytes);
	entry->sh_link = get_field(&pos, 4);
	entry->sh_info = get_field(&pos, 4);
	entry->sh_addralign = get_field(&pos, nbytes);
	entry->sh_entsize = get_field(&pos, nbytes);
}

static char *get_section_name(uint64_t sec_index)
{
	return (char *)(mfile +
			sh_entries[eh.e_shstrndx].sh_offset +
			sh_entries[sec_index].sh_name);
}

/* sh_entries will be allocated by alloc_header_tables */
static void show_section_headers()
{
	struct sh_entry *entry;
	int i;

	 /* return if the file does not contain a section header table */
	if (eh.e_shoff == 0)
		return;

	printf("\nSection Headers:\n");

	/*
	 * Load the values of the section header into entries to print them
	 * later
	 */
	for (i = 0; i < eh.e_shnum; i++)
		get_section_header(i, &sh_entries[i]);

	printf("      Nr   Name                             Type               Address            Offset\n"
	       "           Size                             EntSize            Flags   Link   Info   Align\n");

	/* Print section header data */
	for (i = 0; i < eh.e_shnum; i++) {
		char *sec_name;
		char flag_buf[15] = {};

		entry = &sh_entries[i];
		sec_name = get_section_name(i);
		get_section_flag(entry->sh_flags, flag_buf);

		if (strncmp(sec_name, ".modinfo", 8) == 0) {
			modinfo_off = entry->sh_offset;
			modinfo_len = entry->sh_size;
		} else if (strncmp(sec_name, ".symtab", 7) == 0) {
			tabs[SYMTAB].tab_off = entry->sh_offset;
			tabs[SYMTAB].tab_len = entry->sh_size;
			tabs[SYMTAB].entry_size = entry->sh_entsize;
			tabs[SYMTAB].nentries = tabs[SYMTAB].tab_len /
						tabs[SYMTAB].entry_size;
		} else if (strncmp(sec_name, ".strtab", 7) == 0) {
			tabs[SYMTAB].strtab_off = entry->sh_offset;
			tabs[SYMTAB].strtab_len = entry->sh_size;
		} else if (strncmp(sec_name, ".dynsym", 7) == 0) {
			tabs[DYNTAB].tab_off = entry->sh_offset;
			tabs[DYNTAB].tab_len = entry->sh_size;
			tabs[DYNTAB].entry_size = entry->sh_entsize;
			tabs[DYNTAB].nentries = tabs[DYNTAB].tab_len /
						tabs[DYNTAB].entry_size;
		} else if (strncmp(sec_name, ".dynstr", 7) == 0) {
			tabs[DYNTAB].strtab_off = entry->sh_offset;
			tabs[DYNTAB].strtab_len = entry->sh_size;
		}

		printf("  [%4d]   %-30s   %-16s   %016d   %-d\n"
		       "           %030d   %016d   %-5s   %-4d   %-4d   %-d\n",
				i,
				sec_name,
				get_sh_type(entry->sh_type),
				entry->sh_addr,
				entry->sh_offset,
				entry->sh_size,
				entry->sh_entsize,
				flag_buf,
				entry->sh_link,
				entry->sh_info,
				entry->sh_addralign);
	}
}

/* Show Linux kernel module information. */
static void show_modinfo()
{
	uint64_t cur_len = modinfo_off;
	uint64_t modinfo_end = modinfo_off + modinfo_len;

	if (modinfo_off == 0 || modinfo_len == 0)
		return;

	printf("\nModule Info:\n");

	do {
		cur_len += printf("%s\n", mfile + cur_len);
	} while (cur_len < modinfo_end);
}

static void get_symbol(struct sym_tab *t, size_t sym_index, struct sym_entry *entry)
{
	size_t pos = t->tab_off + (sym_index * t->entry_size);

	entry->st_name = get_field(&pos, 4);

	if (is64bit) {
		entry->st_info = get_field(&pos, 1);
		entry->st_other = get_field(&pos, 1);
		entry->st_shndx = get_field(&pos, 2);
		entry->st_value = get_field(&pos, 4);
		entry->st_size = get_field(&pos, 4);
	} else {
		entry->st_value = get_field(&pos, 4);
		entry->st_size = get_field(&pos, 4);
		entry->st_info = get_field(&pos, 1);
		entry->st_other = get_field(&pos, 1);
		entry->st_shndx = get_field(&pos, 2);
	}
}

static char *get_symbol_name(struct sym_entry *sym, unsigned int tindex)
{
	return (char *)(mfile + tabs[tindex].strtab_off + sym->st_name);
}

static void show_symbol_tab(unsigned int tindex)
{
	struct sym_tab *t = &tabs[tindex];
	unsigned int i;

	if (t->nentries == 0)
		return;

	t->entries = malloc(sizeof(struct sym_entry) * t->nentries);
	if (!t->entries)
		err(1, "malloc %s", tindex == SYMTAB ? "symtab" : "dyntab");

	printf("\nSymbol Table (.%s):\n", tindex == SYMTAB ? "symtab" : "dyntab");
	printf("  Num:                Value       Size       Bind       Type   Visibility   RelToSection   Name\n");
	for (i = 0; i < t->nentries; i++) {
		struct sym_entry *sym = &t->entries[i];
		char sec_rel[25] = {};
		char *sym_type;

		get_symbol(t, i, sym);

		switch (sym->st_shndx) {
		case SHN_ABS:
			sprintf(sec_rel, "%s", "ABS");
			break;
		case SHN_UNDEF:
			sprintf(sec_rel, "%s", "UND");
			break;
		case SHN_LOOS ... SHN_HIOS:
			sprintf(sec_rel, "%s (0x%x)", "OS", sym->st_shndx);
			break;
		default:
			sprintf(sec_rel, "%d", sym->st_shndx);
		}

		sym_type = get_symbol_type(sym);

		printf("%5d: %020lx %10lu %10s %10s   %10s   %12s   %s\n",
				i,
				sym->st_value,
				sym->st_size,
				get_symbol_bind(sym->st_info),
				sym_type,
				get_symbol_visibility(sym->st_other),
				sec_rel,
				strncmp(sym_type, "SECTION", 7) == 0
					? get_section_name(sym->st_shndx)
					: get_symbol_name(sym, tindex));
	}
}

static void get_rel_entry(bool rela, struct sh_entry *she, size_t rel_index,
				struct rela_entry *rel)
{
	size_t pos = she->sh_offset + (rel_index * she->sh_entsize);

	rel->r_offset = get_field(&pos, nbytes);
	rel->r_info = get_field(&pos, nbytes);

	if (rela)
		rel->r_addend = get_field(&pos, nbytes);
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

static void show_relocation_sections()
{
	int i;

	for (i = 0; i < eh.e_shnum; i++) {
		size_t j;
		bool is_rela;
		size_t rel_num;
		struct sh_entry *she = &sh_entries[i];

		/* type == 4 means relocation */
		if (she->sh_type != 4 && she->sh_type != 9)
			continue;

		is_rela = she->sh_type == 4;
		rel_num = she->sh_size / she->sh_entsize;

		printf("\nRelocation section '%s' with %lu entries:\n",
				get_section_name(i), rel_num);

		printf("  Offset        Info          Sym. Index Type                      Sym. Value     Sym. Name + Addend\n");
		for (j = 0; j < rel_num; j++) {
			struct rela_entry entry;
			struct sym_entry *sym;

			get_rel_entry(is_rela, she, j, &entry);

			sym = &tabs[SYMTAB].entries[entry.r_info >> 32];

			printf("  %012lx  %012lx  %10lu %-25s %012lx   %s\n",
					entry.r_offset,
					entry.r_info,
					entry.r_info >> 32,
					get_rel_type(entry.r_info & 0xffffffff),
					sym->st_value,
					strncmp(get_symbol_type(sym), "SECTION", 7) == 0
						? get_section_name(sym->st_shndx)
						: get_symbol_name(sym, SYMTAB)
			);
		}
	}
}

static void alloc_header_tables()
{
	if (eh.e_shnum > 0) {
		sh_entries = malloc(sizeof(struct sh_entry) * eh.e_shnum);
		if (!sh_entries)
			errx(1, "malloc sh_entries");
	}

	if (eh.e_phnum > 0) {
		ph_entries = malloc(sizeof(struct ph_entry) * eh.e_phnum);
		if (!ph_entries)
			errx(1, "malloc ph_entries");
	}
}

static void release_header_tables()
{
	free(sh_entries);
	free(ph_entries);
	if (tabs[DYNTAB].nentries > 0)
		free(tabs[DYNTAB].entries);
	if (tabs[SYMTAB].nentries > 0)
		free(tabs[SYMTAB].entries);
}

int main(int argc, char **argv)
{
	int fd;
	struct stat st;
	if (argc != 2)
		err(1, "Usage: %s <elf file>\n", argv[0]);

	fd = open(argv[1], O_RDONLY);
	if (fd == -1)
		err(1, "%s", argv[1]);

	if (fstat(fd, &st))
		err(1, "%s", argv[1]);

	/* Map the ELF file into memory to avoid further read calls. */
	mfile = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mfile == MAP_FAILED)
		err(1, "%s", argv[1]);

	close(fd);

	get_eh_fields();

	alloc_header_tables();

	show_program_headers();
	show_section_headers();

	show_symbol_tab(DYNTAB);
	show_symbol_tab(SYMTAB);

	show_relocation_sections();

	show_modinfo();

	release_header_tables();

	munmap(mfile, st.st_size);

	return 0;
}
