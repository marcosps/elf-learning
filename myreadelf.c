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

static struct elf_header eh;
static struct sh_entry *sh_entries = NULL;
static struct ph_entry *ph_entries = NULL;

static struct patchable_funcs pfuncs[2] = {
	{ .type = MCOUNT_LOC, .desc = "__mcount_loc" },
	{ .type = PATCHABLE_FUNCTION_ENTRIES, .desc = "__patchable_function_entries" },
};

static struct sym_tab tabs[2] = {
	{ .type = SYMTAB, .desc = "symtab", },
	{ .type = DYNTAB, .desc = "dyntab", },
};

/* Get value mfile starting from offset + len */
static uint64_t get_field(size_t *offset, size_t len)
{
	unsigned char data[9] = {0};

	memcpy(data, mfile + *offset, len);

	*offset += len;

	/* Big enough to store 32 and 64 bit values */
	return *(uint64_t *)data;
}

static char *get_symbol_name(struct sym_entry *sym, unsigned int tindex)
{
	return (char *)(mfile + tabs[tindex].strtab_off + sym->st_name);
}

static char *find_symbol_by_value(long unsigned int value)
{
	int tab = SYMTAB;
	while (tab <= DYNTAB) {
		struct sym_tab *t = &tabs[tab];
		unsigned int i;
		for (i = 0; i < t->nentries; i++) {
			struct sym_entry *sym = &t->entries[i];
			if (sym->st_value == value)
				return get_symbol_name(sym, tab);

		}
		tab++;
	}
	return NULL;
}

static void show_tracing_fentries()
{
	unsigned long p;
	int tab = MCOUNT_LOC;

	while (tab < LAST_PATCH_SECTION) {
		struct patchable_funcs pf = pfuncs[tab];
		if (pf.trace_offset) {
			unsigned long end = pf.trace_offset + pf.trace_len;
			printf("\nTraceable symbols (%s):\n", pf.desc);

			while (pf.trace_offset < end) {
				p = get_field(&pf.trace_offset, 8);
				printf("  %s\t\t%lx\n", find_symbol_by_value(p), p);
			}
		}
		tab++;
	}
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
		} else if (strncmp(sec_name, "__patchable_function_entries", 28) == 0) {
			pfuncs[PATCHABLE_FUNCTION_ENTRIES].trace_offset = entry->sh_offset;
			pfuncs[PATCHABLE_FUNCTION_ENTRIES].trace_len = entry->sh_size;
		} else if (strncmp(sec_name, "__mcount_loc", 12) == 0) {
			pfuncs[MCOUNT_LOC].trace_offset = entry->sh_offset;
			pfuncs[MCOUNT_LOC].trace_len = entry->sh_size;
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

static void show_symbol_tab(unsigned int tindex)
{
	struct sym_tab *t = &tabs[tindex];
	unsigned int i;

	if (t->nentries == 0)
		return;

	t->entries = malloc(sizeof(struct sym_entry) * t->nentries);
	if (!t->entries)
		err(1, "malloc %s", tabs[tindex].desc);

	printf("\nSymbol Table (.%s):\n", tabs[tindex].desc);
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

	show_tracing_fentries();

	show_relocation_sections();

	show_modinfo();

	release_header_tables();

	munmap(mfile, st.st_size);

	return 0;
}
