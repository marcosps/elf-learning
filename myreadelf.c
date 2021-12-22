#include <err.h>
#include <fcntl.h>
#include <stdbool.h> // bool
#include <stdio.h>
#include <stdlib.h> //strtoull
#include <string.h> // memcpy
#include <inttypes.h> //uint64_t
#include <sys/mman.h> // mmap
#include <sys/param.h> //MAX
#include <sys/types.h> //lseek
#include <sys/stat.h> //fstat
#include <unistd.h> //close

static unsigned char *mfile;

static int fd;

static bool is64bit = false;
/* Some fields use 8 bytes when in 64bit ELF files */
static char nbytes;

static unsigned int modinfo_off;
static unsigned int modinfo_len;

#define SYMTAB 0
#define DYNTAB 1

static struct sym_tab {
	unsigned int tab_off;
	unsigned int tab_len;
	unsigned int entry_size;
	unsigned int strtab_off;
	unsigned int strtab_len;
	unsigned int nentries;
} tabs[2] = {};

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

static char *get_ph_type(int type)
{
	if (type == 0)
		return "NULL";
	else if (type == 1)
		return "LOAD";
	else if (type == 2)
		return "DYNAMIC";
	else if (type == 3)
		return "INTEROP";
	else if (type == 4)
		return "NOTE";
	else if (type == 5)
		return "SHLIB";
	else if (type == 6)
		return "PHDR";
	else if (type == 7)
		return "TLS";
	else if (type == 0x60000000)
		return "LOOS";
	else if (type == 0x6FFFFFFF)
		return "HIOS";
	// begin Defined in elf.h
	else if (type == 0x6474e550)
		return "GNU_EH_FRAME";
	else if (type == 0x6474e551)
		return "GNU_STACK";
	else if (type == 0x6474e552)
		return "GNU_RELRO";
	// enf defined by elf.h
	else if (type == 0x70000000)
		return "LOPROC";
	else if (type == 0x7FFFFFFF)
		return "HIPROC";
	return "UNKNOWN";
}

static char *get_sh_type(uint64_t type)
{
	if (type == 0)
		return "NULL";
	else if (type == 1)
		return "PROGBITS";
	else if (type == 2)
		return "SYMTAB";
	else if (type == 3)
		return "STRTAB";
	else if (type == 4)
		return "RELA";
	else if (type == 5)
		return "HASH";
	else if (type == 6)
		return "DYNAMIC";
	else if (type == 7)
		return "NOTE";
	else if (type == 8)
		return "NOBITS";
	else if (type == 9)
		return "REL";
	else if (type == 10)
		return "SHLIB";
	else if (type == 11)
		return "DYNLIB";
	else if (type == 12)
		return "INIT_ARRAY";
	else if (type == 13)
		return "FINI_ARRAY";
	else if (type == 14)
		return "PREINIT_ARRAY";
	else if (type == 15)
		return "GROUP";
	else if (type == 16)
		return "SYMTAB_SHNDX";
	else if (type == 17)
		return "NUM";
	else if (type == 0x60000000)
		return "LOOS";
	// begin defined in /usr/include/elf.h
	else if (type == 0x6ffffff5)
	       return "GNU_ATTRIBUTES";
	else if (type == 0x6ffffff6)
		return "GNU_HASH";
	else if (type == 0x6ffffff7)
		return "GNU_LIBLIST";
	else if (type == 0x6ffffff8)
		return "CHECKSUM";
	else if (type == 0x6ffffffa)
		return "LOSUNW";
	else if (type == 0x6ffffffa)
		return "SUNW_move";
	else if (type == 0x6ffffffb)
		return "SUNW_COMDAT";
	else if (type == 0x6ffffffc)
		return "SUNW_syminfo";
	else if (type == 0x6ffffffd)
		return "GNU_verdef";
	else if (type == 0x6ffffffe)
		return "GNU_verneed";
	else if (type == 0x6fffffff)
		return "GNU_versym";
	else if (type == 0x6fffffff)
		return "HISUNW";
	else if (type == 0x6fffffff)
		return "HIOS";
	else if (type == 0x70000000)
		return "LOPROC";
	else if (type == 0x7fffffff)
		return "HIPROC";
	else if (type == 0x80000000)
		return "LOUSER";
	else if (type == 0x8fffffff)
		return "HIUSER";
	return "UNKNOWN";
}

static char *get_symbol_type(unsigned char info)
{
	unsigned char val = info & 0xf;
	switch (val) {
	case 0:
		return "NOTYPE";
	case 1:
		return "OBJECT";
	case 2:
		return "FUNC";
	case 3:
		return "SECTION";
	case 4:
		return "FILE";
	case 5:
		return "COMMON";
	case 6:
		return "TLS";
	case 7:
		return "NUM";
	case 10:
		return "GNU_IFUNC";
	default:
		return "UNKNOWN";
	}
}

static char *get_symbol_bind(unsigned char info)
{
	unsigned char val = info >> 4;
	switch (val) {
	case 0:
		return "LOCAL";
	case 1:
		return "GLOBAL";
	case 2:
		return "WEAK";
	case 3:
		return "NUM";
	case 10:
		return "GNU_UNIQUE";
	default:
		return "UNKNOWN";
	}
}

static char *get_symbol_visibility(unsigned char val)
{
	switch (val) {
	case 0:
		return "DEFAULT";
	case 1:
		return "INTERNAL";
	case 2:
		return "HIDDEN";
	case 3:
		return "PROTECTED";
	default:
		return "UNKNOWN";
	}
}

/* Prints the entry point, ph offset and sh offset */
static uint64_t get_field(size_t offset, size_t len)
{
	unsigned char data[9] = {0};
	/* Big enough to store 32 and 64 bit values */
	uint64_t val;

	memcpy(data, mfile + offset, len);
	/* TODO: How to convert it by using glibc? */
	val = *(uint64_t *)data;

	return val;
}

static void get_eh_fields()
{
	size_t pos = 16;

	if (mfile[0] != 0x7f)
		errx(1, "Not an ELF file");

	if (mfile[4] == 2)
		is64bit = true;

	eh.e_type = get_field(pos, 2);

	pos += 2;
	eh.e_machine = get_field(pos, 2);

	pos += 2;
	eh.e_version = get_field(pos, 4);

	/* The number of bytes of some fields in the Elf Header. */
	nbytes = is64bit ? 8 : 4;

	pos += 4;
	eh.e_entry = get_field(pos, nbytes);

	pos += nbytes;
	eh.e_phoff = get_field(pos, nbytes);

	pos += nbytes;
	eh.e_shoff = get_field(pos, nbytes);

	pos += nbytes;
	eh.e_flags = get_field(pos, 4);

	pos += 4;
	eh.e_ehsize = get_field(pos, 2);

	pos += 2;
	eh.e_phentsize = get_field(pos, 2);

	pos += 2;
	eh.e_phnum = get_field(pos, 2);

	pos += 2;
	eh.e_shentsize = get_field(pos, 2);

	pos += 2;
	eh.e_shnum = get_field(pos, 2);

	pos += 2;
	eh.e_shstrndx = get_field(pos, 2);

	printf("ELF Header\n");
	printf("==========\n");

	printf("Magic numbers: %#0x - %c%c%c\n", mfile[0], mfile[1], mfile[2], mfile[3]);
	printf("The ELF file was compiled for %s endian machines\n", mfile[5] == 1 ? "little" : "big");
	printf("OS ABI: 0x%d (0 == System V)\n", mfile[7]);

	printf("Object type: 0x%x\n", eh.e_type);
	printf("ISA: 0x%x\n", eh.e_machine);
	printf("ELF version: %d\n", eh.e_version);
	printf("Entry point: 0x%lx\n", eh.e_entry);
	printf("Program header offset (bytes): %lu\n", eh.e_phoff);
	printf("Section header offset (bytes): %lu\n", eh.e_shoff);
	printf("Flags: 0x%x\n", eh.e_flags);
	printf("Size of this header (bytes): %d\n", eh.e_ehsize);
	printf("Size of program header (bytes): %d\n", eh.e_phentsize);
	printf("Number of program headers: %d\n", eh.e_phnum);
	printf("Size of section headers (bytes): %d\n", eh.e_shentsize);
	printf("Number of section headers: %d\n", eh.e_shnum);
	printf("Section header string table index: %d\n", eh.e_shstrndx);
}

static void get_prog_flags(uint64_t flags, char *flag_buf)
{
	flag_buf[0] = flags & 0x4 ? 'R' : ' ';
	flag_buf[1] = flags & 0x2 ? 'W' : ' ';
	flag_buf[2] = flags & 0x1 ? 'E' : ' ';
}

static void get_section_flag(uint64_t flags, char *flag_buf)
{
	int pos = 0;

	if (flags & 0x1) /* SHF_WRITE */
		flag_buf[pos++] = 'W';
	if (flags & 0x2) /* SHF_ALLOC */
		flag_buf[pos++] = 'A';
	if (flags & 0x4) /* SHF_EXECINSTR */
		flag_buf[pos++] = 'X';
	if (flags & 0x10) /* SHF_MERGE */
		flag_buf[pos++] = 'M';
	if (flags & 0x20) /* SHF_STRINGS */
		flag_buf[pos++] = 'S';
	if (flags & 0x40) /* SHF_INFO_LINK */
		flag_buf[pos++] = 'I';
	if (flags & 0x80) /* SHF_LINK_ORDER */
		flag_buf[pos++] = 'L';
	if (flags & 0x100) /* SHF_OS_NONCONFORMING */
		flag_buf[pos++] = 'O';
	if (flags & 0x200) /* SHF_GROUP */
		flag_buf[pos++] = 'G';
	if (flags & 0x400) /* SHF_TLS */
		flag_buf[pos++] = 'T';
	if (flags & 0x0ff00000) /* SHF_MASKOS */
		flag_buf[pos++] = '?'; //FIXME
	if (flags & 0xf0000000) /* SHF_MASKPROC */
		flag_buf[pos++] = '?'; //FIXME
	if (flags & 0x4000000) /* SHF_ORDERED */
		flag_buf[pos++] = 'O';
	if (flags & 0x8000000) /* SHF_EXCLUDE */
		flag_buf[pos++] = 'E';
}

static void get_program_header(size_t ph_index, struct ph_entry *entry)
{
	size_t pos = eh.e_phoff + (ph_index * eh.e_phentsize);

	/* Type is 4 bytes both in 32 and 64 bit */
	entry->p_type = get_field(pos, 4);
	pos += 4;

	/* On 64 bit, the flags field comes after the type */
	if (is64bit) {
		entry->p_flags = get_field(pos, 4);
		pos += 4;
	}

	entry->p_offset = get_field(pos, nbytes);
	pos += nbytes;

	entry->p_vaddr = get_field(pos, nbytes);
	pos += nbytes;

	entry->p_paddr = get_field(pos, nbytes);
	pos += nbytes;

	entry->p_filesz = get_field(pos, nbytes);
	pos += nbytes;

	entry->p_memsz = get_field(pos, nbytes);
	pos += nbytes;

	/* On 32bit, the flag field exists after the MemSize */
	if (!is64bit) {
		entry->p_flags = get_field(pos, 4);
		pos += 4;
	}

	entry->p_align = get_field(pos, nbytes);
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
			printf("Interpreter: %s\n", mfile + entry->p_offset);
	}

	printf("\nProgram Headers:\n");
	for (i = 0; i < eh.e_phnum; i++) {
		char flag_buf[4] = {};

		entry = &ph_entries[i];
		get_prog_flags(entry->p_flags, flag_buf);
		printf("  Type: %20s\tOffset: 0x%lx\tVirtAddr: 0x%lx\tPhysAddr: 0x%lx\tFileSz (bytes): %lu\tMemSz (bytes): %lu\tFlags: %s"
				"\n",
				get_ph_type(entry->p_type),
				entry->p_offset,
				entry->p_vaddr,
				entry->p_paddr,
				entry->p_filesz,
				entry->p_memsz,
				flag_buf
		      );
	}

	printf("\n");
}

static void get_section_header(size_t sh_index, struct sh_entry *entry)
{
	int pos = eh.e_shoff + (sh_index * eh.e_shentsize);

	entry->sh_name = get_field(pos, 4);

	pos += 4;
	entry->sh_type = get_field(pos, 4);

	pos += 4;
	entry->sh_flags = get_field(pos, nbytes);

	pos += nbytes;
	entry->sh_addr = get_field(pos, nbytes);

	pos += nbytes;
	entry->sh_offset = get_field(pos, nbytes);

	pos += nbytes;
	entry->sh_size = get_field(pos, nbytes);

	pos += nbytes;
	entry->sh_link = get_field(pos, 4);

	pos += 4;
	entry->sh_info = get_field(pos, 4);

	pos += 4;
	entry->sh_addralign = get_field(pos, nbytes);

	pos += nbytes;
	entry->sh_entsize = get_field(pos, nbytes);
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
		       "           %030d   %016d   %5s   %-4d   %4d   %d\n",
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
	int pos = t->tab_off + (sym_index * t->entry_size);

	entry->st_name = get_field(pos, 4);

	pos += 4;
	if (is64bit) {
		entry->st_info = get_field(pos, 1);
		pos += 1;
		entry->st_other = get_field(pos, 1);
		pos += 1;
		entry->st_shndx = get_field(pos, 2);
		pos += 2;
		entry->st_value = get_field(pos, 4);
		pos += 4;
		entry->st_size = get_field(pos, 4);
	} else {
		entry->st_value = get_field(pos, 4);
		pos += 4;
		entry->st_size = get_field(pos, 4);
		pos += 4;
		entry->st_info = get_field(pos, 1);
		pos += 1;
		entry->st_other = get_field(pos, 1);
		pos += 1;
		entry->st_shndx = get_field(pos, 2);
	}
}

static void show_symbol_tab(unsigned int tindex)
{
	struct sym_tab *t = &tabs[tindex];
	struct sym_entry syms[t->nentries];
	unsigned int i;

	if (t->nentries == 0)
		return;

	if (tindex == SYMTAB)
		printf("\nSymbol Table (.symtab):\n");
	else
		printf("\nSymbol Table (.dyntab):\n");

	printf("  Num:                Value       Size       Bind       Type   Visibility   RelToSection   Name\n");
	for (i = 0; i < t->nentries; i++) {
		char sec_rel[10] = {};
		char *sym_type;

		get_symbol(t, i, &syms[i]);

		switch (syms[i].st_shndx) {
		case 0xfff1:
			sprintf(sec_rel, "%s", "ABS");
			break;
		case 0:
			sprintf(sec_rel, "%s", "UND");
			break;
		default:
			sprintf(sec_rel, "%d", syms[i].st_shndx);
		}

		sym_type = get_symbol_type(syms[i].st_info);

		printf("%5d: %020lx %10lu %10s %10s   %10s   %12s   %s\n",
				i,
				syms[i].st_value,
				syms[i].st_size,
				get_symbol_bind(syms[i].st_info),
				sym_type,
				get_symbol_visibility(syms[i].st_other),
				sec_rel,
				strncmp(sym_type, "SECTION", 7) == 0
					? get_section_name(syms[i].st_shndx)
					: (char *)(mfile + t->strtab_off + syms[i].st_name));
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
}

int main(int argc, char **argv)
{
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

	show_modinfo();

	show_symbol_tab(DYNTAB);
	show_symbol_tab(SYMTAB);

	release_header_tables();

	munmap(mfile, st.st_size);

	return 0;
}
