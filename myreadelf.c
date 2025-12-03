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

/* Size of the symbol table entry */
size_t sym_size;

static unsigned int modinfo_off;
static unsigned int modinfo_len;

static struct elf_header eh;
static struct sh_entry *sh_entries = NULL;
static struct ph_entry *ph_entries = NULL;

static size_t patchable_num;
/* Is 1024 mcount entries enough? */
static struct patchable_funcs pfuncs[1024];

static uint64_t start_mcount_loc, stop_mcount_loc;

static struct sym_tab *tabs[2];

/* Get value mfile starting from offset + len */
static uint64_t get_field(size_t *offset, size_t len)
{
	uint64_t data = 0;

	memcpy(&data, mfile + *offset, len);

	*offset += len;

	/* Big enough to store 32 and 64 bit values */
	return data;
}

/* Return the symbol name by looking at the symbol index inside the SYMTAB */
static char *get_symbol_name(uint32_t st_name)
{
	return (char *)(mfile + tabs[SYMTAB]->strtab_off + st_name);
}

#define SYM_FIELD(sym, field) \
	is64bit ? ((struct sym_entry_64 *)sym)->field : ((struct sym_entry_32 *)sym)->field

#define SYM_OBJ(_tab, _index) \
	is64bit ? (void *)&((struct sym_entry_64 *)_tab->entries)[_index] : \
		  (void *)&((struct sym_entry_32 *)_tab->entries)[_index]

/* Used to sort the SYMTAB symbols by their address ()st_value */
static int compare_symbols(const void *sym1, const void *sym2)
{
	struct sym_entry_64 *s1 = (struct sym_entry_64 *)sym1;
	struct sym_entry_64 *s2 = (struct sym_entry_64 *)sym2;

	if (s1->st_value < s2->st_value)
		return -1;
	if (s1->st_value > s2->st_value)
		return 1;

	return 0;
}

/* Return the symbol from symbol tab using it's address (st_value) */
static char *find_symbol_by_value(uint64_t value)
{
	/* Search for the symbol name */
	struct sym_entry_64 key, *res;
	key.st_value = value;

	res = bsearch(&key,
	              tabs[SYMTAB]->entries,
	              tabs[SYMTAB]->nentries,
	              sizeof(struct sym_entry_64),
		              compare_symbols);

	if (!res)
		return NULL;

	return get_symbol_name(res->st_name);
}

/**
 * Find the name of a section by looking at the section header table entry
 * (e_shstrndx) using the section header index.
 */
static char *get_section_name(uint64_t sec_index)
{
	return (char *)(mfile +
			sh_entries[eh.e_shstrndx].sh_offset +
			sh_entries[sec_index].sh_name);
}

/* Get relocation entry informantion from the ELF file */
static void get_rel_entry(bool rela, struct sh_entry *she, size_t rel_index,
				struct rela_entry *rel)
{
	size_t pos = she->sh_offset + (rel_index * she->sh_entsize);

	if (rela)
		memcpy(rel, mfile + pos, 3 * nbytes);
	else
		memcpy(rel, mfile + pos, 2 * nbytes);
}

/* Expects the symtab to be ordered */
static void find_symbol_by_addr_and_sec(uint64_t addr, size_t sec)
{
	size_t end = tabs[SYMTAB]->nentries;

	for (size_t i = 0; i < end; i++) {
		struct sym_entry_64 *sym = &tabs[SYMTAB]->entries[i];

		if (sym->st_value < addr)
			continue;

		if (sym->st_value > addr)
			break;

		if (sym->st_shndx < sec)
			continue;

		if (sym->st_shndx > sec)
			break;

		printf("\t%lx %s (%s)\n", sym->st_value,
		       get_symbol_name(sym->st_name),
		       get_section_name(sym->st_shndx));
	}
}

static void process_mcount_rela(size_t sec_index) {
	struct sh_entry *she = &sh_entries[sec_index];
	size_t rel_num = she->sh_size / she->sh_entsize;

	printf("We can have more entries than expected because opf symbol alias\n");
	for (size_t i = 0; i < rel_num; i++) {
		struct rela_entry entry;
		size_t sym_section;
		int64_t sym_addr;

		get_rel_entry(she->sh_type == SHT_RELA, she, i, &entry);
		sym_section = is64bit ? entry.r_info >> 32 : entry.r_info >> 8;
		sym_addr = entry.r_addend;

		find_symbol_by_addr_and_sec(sym_addr, sym_section);
	}
}

/**
 * Print all entries in specific ELF sections known to contain symbols that
 * are able to be patched. This involves the sections like
 * __patchable_function_entries and __mcount_loc, for userspace programs.
 *
 * This function is also able to print all addresses and symbol names from
 * the current __start_mcount_loc and __stop_mcount_loc, which contain all
 * the places inside the kernel that are able to be live patched. The content
 * of this memory region is an array of addresses, and using these addresses
 * it's possible to grab the symbol names.
 */
static void show_tracing_fentries()
{
	for (size_t i = 0; i < patchable_num; i++) {
		struct patchable_funcs pf = pfuncs[i];
		if (pf.len > 0) {
			unsigned long end = pf.offset + pf.len;
			size_t data_len = sizeof(unsigned long *);
			unsigned long nentries = (end - pf.offset) / data_len;
			printf("\nFound %lu traceable symbol(s) on section %s, starting on offset %lx:\n",
					nentries, patch_tabs[pf.type], pf.offset);

			/*
			 * Detected a kernel module. The mcount/pactchable tables
			 * will be empty at compilation time, since the exact
			 * position of the symbols isn't known until relocation
			 * is done by the kernel when the module is loaded.
			 * Since ftrace needs the address of the funtions, there
			 * is nothing to be right now.
			 */
			if (modinfo_off != 0) {
				process_mcount_rela(pf.rela_she_index);
			} else {
				while (pf.offset < end) {
					/* each pointer has 8 bytes */
					uint64_t p = get_field(&pf.offset, data_len);
					printf("  %s\t\t%lx\n", find_symbol_by_value(p), p);
				}
			}
		} else {
			printf("\nSection %s at offset %lu has no content: sh_size is zero\n",
					patch_tabs[pf.type], pf.offset);
		}
	}

	/*
	 * The kernel is different, so we need to go through the array that is
	 * limited by these two symbols. The content is the address of each
	 * function that is able to be patched/traced/probed/etc.
	 */
	if (stop_mcount_loc && start_mcount_loc) {
		int zeroed_total = 0;
		printf("\nFound (%ld) mcount symbols for Linux kernel.\n"
		       "Starting at %lx (%ld) and stopping at %lx (%ld).\n"
		       "Printing the addresses of the functions that can be "
		       "traced:\n",
		       (stop_mcount_loc - start_mcount_loc) / nbytes,
		       start_mcount_loc, start_mcount_loc, stop_mcount_loc, stop_mcount_loc);

		for (size_t pos = start_mcount_loc; pos < stop_mcount_loc;) {
			uint64_t sym_addr = get_field(&pos, nbytes);

			/* Some symbols have addr as 0, so just skip them */
			if (sym_addr == 0) {
				zeroed_total++;
				continue;
			}

			printf("\t%lx %s\n", sym_addr,
					   find_symbol_by_value(sym_addr));
		}

		if (zeroed_total)
			printf("Skipped %d entries with address set as 0.\n", zeroed_total);
	}
}

/**
 * Parse the first ELF header section, containing some basic information about
 * the ELF file being parsed.
 */
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
	sym_size = is64bit ? sizeof(struct sym_entry_64) : sizeof(struct sym_entry_32);

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

/* Sets the flags for a specific program header */
static void get_prog_flags(uint64_t flags, char *flag_buf)
{
	flag_buf[0] = flags & 0x4 ? 'R' : ' ';
	flag_buf[1] = flags & 0x2 ? 'W' : ' ';
	flag_buf[2] = flags & 0x1 ? 'E' : ' ';
}

/* Get all fields from a program header */
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

/* Print the information about all the program headers */
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

/* Set data from a section header from the ELF file */
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

/**
 * Iterate and print information about section headers. When a symbol table is
 * found it also allocated memory for all the symbol that will be parsed
 * later.
 */
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
		size_t nentries;

		entry = &sh_entries[i];
		sec_name = get_section_name(i);
		get_section_flag(entry->sh_flags, flag_buf);

		if (strncmp(sec_name, ".modinfo", 8) == 0) {
			modinfo_off = entry->sh_offset;
			modinfo_len = entry->sh_size;
		} else if (strncmp(sec_name, ".symtab", 7) == 0) {
			nentries = entry->sh_size / entry->sh_entsize;
			tabs[SYMTAB] = malloc(sizeof(struct sym_tab) + nentries * sym_size);
			tabs[SYMTAB]->sh_entry = i;
			tabs[SYMTAB]->desc = "symtab";
			tabs[SYMTAB]->tab_off = entry->sh_offset;
			tabs[SYMTAB]->tab_len = entry->sh_size;
			tabs[SYMTAB]->entry_size = entry->sh_entsize;
			tabs[SYMTAB]->nentries = nentries;

		} else if (strncmp(sec_name, ".strtab", 7) == 0) {
			tabs[SYMTAB]->strtab_off = entry->sh_offset;
			tabs[SYMTAB]->strtab_len = entry->sh_size;

		} else if (strncmp(sec_name, ".dynsym", 7) == 0) {
			nentries = entry->sh_size / entry->sh_entsize;
			tabs[DYNTAB] = malloc(sizeof(struct sym_tab) + nentries * sym_size);
			tabs[DYNTAB]->sh_entry = i;
			tabs[DYNTAB]->desc = "dynsym";
			tabs[DYNTAB]->tab_off = entry->sh_offset;
			tabs[DYNTAB]->tab_len = entry->sh_size;
			tabs[DYNTAB]->entry_size = entry->sh_entsize;
			tabs[DYNTAB]->nentries = nentries;

		} else if (strncmp(sec_name, ".dynstr", 7) == 0) {
			tabs[DYNTAB]->strtab_off = entry->sh_offset;
			tabs[DYNTAB]->strtab_len = entry->sh_size;

		} else if (strncmp(sec_name, "__patchable_function_entries", 28) == 0) {
			pfuncs[patchable_num].type = PATCHABLE_FUNCTION_ENTRIES;
			pfuncs[patchable_num].offset = entry->sh_offset,
			pfuncs[patchable_num].len = entry->sh_size;
			patchable_num++;

		} else if (strncmp(sec_name, ".rela__patchable_function_entries", 33) == 0) {
			/* should be related to the last added patchable section */
			pfuncs[patchable_num-1].rela_she_index = i;

		} else if (strncmp(sec_name, "__mcount_loc", 12) == 0) {
			/* should be related to the last added mcount section */
			pfuncs[patchable_num].type = MCOUNT_LOC;
			pfuncs[patchable_num].offset = entry->sh_offset,
			pfuncs[patchable_num].len = entry->sh_size;
			patchable_num++;

		} else if (strncmp(sec_name, ".rela__mcount_loc", 17) == 0) {
			pfuncs[patchable_num-1].rela_she_index = i;

		}

		printf("  [%4d]   %-30s   %-16s   %016x   %x\n"
		       "           %030x   %016d   %-5s   %-4d   %-4d   %-d\n",
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

/**
 * Copy the symbol data from the ELF file using the symbol size and the file
 * offset regarding the symbol info.
 */
static void get_symbol(struct sym_tab *t, size_t sym_index, void *entry)
{
	size_t pos = t->tab_off + (sym_index * t->entry_size);
	memcpy(entry, mfile + pos, sym_size);
}

/* Populate the symbol tab, being SYMTAB or DYNTAB */
static void load_symbol_tab(unsigned int tindex)
{
	struct sym_tab *t = tabs[tindex];
	unsigned int i;

	if (!t || t->nentries == 0)
		return;

	for (i = 0; i < t->nentries; i++) {
		get_symbol(t, i, &t->entries[i]);

		void *sym = &t->entries[i];

		char *sym_type = get_symbol_type(SYM_FIELD(sym, st_info));

		/* Search for the mcount_loc symbols, and they are set as NOTYPE */
		if (strncmp(sym_type, "NOTYPE", 6))
			continue;

		uint16_t sym_section = SYM_FIELD(sym, st_shndx);

		if (sym_section >= SHN_ABS)
			continue;

		/* Calculate the offset of the symbol inside the section. */
		uint64_t sym_offset = (uint64_t)(SYM_FIELD(sym, st_value)) -
			 	sh_entries[sym_section].sh_addr +
			 	sh_entries[sym_section].sh_offset;

		char *sym_name = get_symbol_name(SYM_FIELD(sym, st_name));

		if (strncmp(sym_name, "__stop_mcount_loc", 17) == 0)
			stop_mcount_loc = sym_offset;
		else if (strncmp(sym_name, "__start_mcount_loc", 18) == 0)
			start_mcount_loc = sym_offset;
	}
}

/* Print information about a symbol tab, being SYMTAB or DYNTAB */
static void show_symbol_tab(unsigned int tindex)
{
	struct sym_tab *t = tabs[tindex];
	unsigned int i;

	if (!t || t->nentries == 0)
		return;

	printf("\nSymbol Table (.%s) contains %d entries:\n", t->desc, t->nentries);
	printf("  Num:                Value       Size       Type       Bind   Visibility   RelToSection   Name\n");
	for (i = 0; i < t->nentries; i++) {
		void *sym = &t->entries[i];
		/* bit enough for 32 and 64bit variants */
		uint16_t st_shndx = SYM_FIELD(sym, st_shndx);

		char sec_rel[25] = {};
		switch (st_shndx) {
		case SHN_ABS:
			sprintf(sec_rel, "%s", "ABS");
			break;
		case SHN_UNDEF:
			sprintf(sec_rel, "%s", "UND");
			break;
		case SHN_LOOS ... SHN_HIOS:
			if (st_shndx == SHN_LIVEPATCH)
				sprintf(sec_rel, "OS (livepatch)");
			else
				sprintf(sec_rel, "OS (0x%x)", st_shndx);
			break;
		default:
			sprintf(sec_rel, "%d", st_shndx);
		}

		char *sym_type = get_symbol_type(SYM_FIELD(sym, st_info));

		printf("%5d: %010lx %10lu %10s %10s   %10s   %12s   %s\n",
				i,
				SYM_FIELD(sym, st_value),
				SYM_FIELD(sym, st_size),
				sym_type,
				get_symbol_bind(SYM_FIELD(sym, st_info)),
				get_symbol_visibility(SYM_FIELD(sym, st_other)),
				sec_rel,
				strncmp(sym_type, "SECTION", 7) == 0
					? get_section_name(st_shndx)
					: get_symbol_name(SYM_FIELD(sym, st_name)));
	}
}

/* Print all the entries in the relocation table */
static void show_relocation_sections()
{
	int i;

	for (i = 0; i < eh.e_shnum; i++) {
		size_t j;
		size_t rel_num;
		struct sh_entry *she = &sh_entries[i];

		if (she->sh_type != SHT_RELA && she->sh_type != SHT_REL)
			continue;

		rel_num = she->sh_size / she->sh_entsize;

		printf("\nRelocation section '%s' with %lu entries:\n",
				get_section_name(i), rel_num);

		printf("  Offset        Info          Sym. Index Type                      Sym. Value     Sym. Name + Addend\n");
		for (j = 0; j < rel_num; j++) {
			struct rela_entry entry;
			size_t rela_sym;

			/* For relocation sections the sh_link field contains
			 * the index to a symbol table section */
			struct sym_tab *tab;
			if (tabs[SYMTAB] && tabs[SYMTAB]->sh_entry == she->sh_link) {
				tab = tabs[SYMTAB];
			} else {
				tab = tabs[DYNTAB];
			}

			get_rel_entry(she->sh_type == SHT_RELA, she, j, &entry);

			rela_sym = is64bit ? entry.r_info >> 32 : entry.r_info >> 8;

			void *sym = SYM_OBJ(tab, rela_sym);

			printf("  %012lx  %012lx  %10lx %-25s %012lx   %s %s %llx\n",
					entry.r_offset,
					entry.r_info,
					rela_sym,
					get_rel_type(entry.r_info & 0xffffffff),
					SYM_FIELD(sym, st_value),
					(int)(SYM_FIELD(sym, st_info)) == STT_SECTION
						? get_section_name(SYM_FIELD(sym, st_shndx))
						: get_symbol_name(SYM_FIELD(sym, st_name)),
					(entry.r_addend > -1) ? "+" : "-",
					llabs(entry.r_addend)
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

/**
 * Sort all the symbol in SYMTAB. This is necessary because the symbols are
 * searched on using a binary search later on.
 */
static void sort_symbols()
{
	if (!tabs[SYMTAB] || tabs[SYMTAB]->nentries == 0)
		return;

	qsort(tabs[SYMTAB]->entries, tabs[SYMTAB]->nentries,
	      sizeof(struct sym_entry_64), compare_symbols);
}

static void release_header_tables()
{
	free(sh_entries);
	free(ph_entries);
	free(tabs[DYNTAB]);
	free(tabs[SYMTAB]);
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

	load_symbol_tab(DYNTAB);
	show_symbol_tab(DYNTAB);

	load_symbol_tab(SYMTAB);
	show_symbol_tab(SYMTAB);

	show_relocation_sections();

	sort_symbols();

	show_tracing_fentries();

	show_modinfo();

	release_header_tables();

	munmap(mfile, st.st_size);

	return 0;
}
