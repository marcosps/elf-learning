#include <err.h>
#include <fcntl.h>
#include <stdbool.h> // bool
#include <stdio.h>
#include <stdlib.h> //strtoull
#include <string.h> // memcpy
#include <inttypes.h> //uint64_t
#include <sys/types.h> //lseek
#include <unistd.h> //close

static int fd;
static uint64_t ph_off;
static uint64_t ph_size;
static uint64_t ph_num;

static uint64_t sh_off;
static uint64_t sh_size;
static uint64_t sh_num;

static uint64_t sh_strndx;

static bool is64bit = false;

static unsigned char elf_header[64];
static unsigned char *prog_header;
static unsigned char *section_header;

struct sh_entry {
	int sh_name;
	int sh_type;
	int sh_flags;
	int sh_addr;
	int sh_offset;
	int sh_size;
};

static char *get_prog_type(int type)
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
	return "UNKONWN";
}

/* Prints the entry point, ph offset and sh offset */
static uint64_t show_var_fields(char *msg, unsigned char *buf, size_t offset,
				size_t nbytes, bool hex, bool print)
{
	unsigned char data[9] = {0};
	/* Big enough to store 32 and 64 bit values */
	uint64_t val;

	memcpy(data, buf + offset, nbytes);
	/* TODO: How to convert it by using glibc? */
	val = *(uint64_t *)data;

	if (!print)
		return val;

	if (hex)
		printf("%s: 0x%lx\n", msg, val);
	else
		printf("%s: %lu\n", msg, val);

	return val;
}

static uint64_t show_var_field(char *msg, size_t offset, size_t nbytes, bool hex)
{
	return show_var_fields(msg, elf_header, offset, nbytes, hex, true);
}

static uint64_t show_prog_field(char *msg, size_t offset, size_t nbytes, bool hex)
{
	return show_var_fields(msg, prog_header, offset, nbytes, hex, true);
}

static uint64_t get_prog_field(size_t offset, size_t nbytes)
{
	return show_var_fields("", prog_header, offset, nbytes, false, false);
}

static uint64_t get_section_field(size_t offset, size_t nbytes)
{
	return show_var_fields("", section_header, offset, nbytes, false, false);
}

/* To understand what are the indexes in the elf_header, read the ELF Header format */
static void show_ident()
{
	int ret;

	printf("Magic numbers: %#0x - %c%c%c\n", elf_header[0], elf_header[1], elf_header[2], elf_header[3]);

	/* If the file is an 64bit ELF file, read the additional 8 bytes */
	if (elf_header[4] == 2) {
		/*
		 * store the additional data at the end of the previously read
		 * data
		 * */
		is64bit = true;
		ret = read(fd, elf_header + 52, 12);
		if (ret == -1)
			errx(1, "read");
	}

	printf("The ELF file was compiled for %s endian machines\n", elf_header[5] == 1 ? "little" : "big");
	// elf_header[6] == ELF version, which is always 1 == current
	printf("OS ABI: 0x%d (0 == System V)\n", elf_header[7]);
	// elf_header[8] == ABIVERSION, which we don't care
	// elf_header[9-15] == UNUSED == EI_PAD
}

static void show_header_fields()
{
	int ret;
	size_t nbytes;
	size_t pos;

	/*
	 * First read 52 bytes, which is the size of the ELF header table for
	 * 32bit binaries, and if we detect a 64 bit binary, read more 8 bytes
	 * (64 in total)
	 */
	ret = read(fd, elf_header, 52);
	if (ret == -1)
		err(1, "fd %d", fd);

	if (elf_header[0] != 0x7f)
		errx(1, "Not an ELF file");

	printf("ELF Header\n");
	printf("==========\n");

	show_ident();

	// e_type
	show_var_field("OBject type", 16, 2, true);
	// e_machine
	show_var_field("ISA", 18, 2, true);
	// e_version
	show_var_field("ELF version", 20, 4, false);

	/*
	 * The number of bytes in field. If it's 64bit (elf_header[4] == 2),
	 * it's 8 bytes, otherwise is 4.
	 */
	nbytes = is64bit ? 8 : 4;

	pos = 24;
	// e_entry
	show_var_field("Entry point", pos, nbytes, true);

	// e_phoff
	pos += nbytes;
	ph_off = show_var_field("Program header offset (bytes)", pos, nbytes, false);

	// e_shoff
	pos += nbytes;
	sh_off = show_var_field("Section header offset (bytes)", pos, nbytes, false);

	// e_flags
	pos += nbytes;
	show_var_field("Flags: ", pos, 4, true);

	// e_ehsize
	pos += 4;
	show_var_field("Size of this header (bytes) ", pos, 2, false);

	// e_phentsize
	pos += 2;
	ph_size = show_var_field("Size of program header (bytes) ", pos, 2, false);

	// e_phnum
	pos += 2;
	ph_num = show_var_field("Number of program headers", pos, 2, false);

	// e_shentsize
	pos += 2;
	sh_size = show_var_field("Size of section headers (bytes)", pos, 2, false);

	// e_shnum
	pos += 2;
	sh_num = show_var_field("Number of section headers", pos, 2, false);

	// e_shstrndx
	pos += 2;
	sh_strndx = show_var_field("Section header string table index", pos, 2, false);

	printf("\n");
}

static void show_prog_flags(int pos)
{
	uint64_t flags;
	// p_flags
	flags = get_prog_field(pos, 4);
	printf("Flags: %c%c%c\n", flags & 0x4 ? 'R' : ' ',
				flags & 0x2 ? 'W' : ' ',
				flags & 0x1 ? 'E' : ' ');
}

static void show_prog_header()
{
	size_t nbytes = is64bit ? 8 : 4;
	size_t pos = 0;
	int type;

	/* Type is 4 bytes both in 32 and 64 bit */
	// p_type
	type = get_prog_field(pos, 4);
	printf("Type: %s\n", get_prog_type(type));
	pos += 4;

	/* On 64 bit, the flags field comes after the type */
	if (is64bit) {
		show_prog_flags(pos);
		pos += 4;
	}

	// p_offset
	show_prog_field("Offset", pos, nbytes, true);
	pos += nbytes;

	// p_vaddr
	show_prog_field("VirtAddr", pos, nbytes, true);
	pos += nbytes;

	// p_paddr
	show_prog_field("PhysAddr", pos, nbytes, true);
	pos += nbytes;

	// p_filesz
	show_prog_field("FileSize (bytes)", pos, nbytes, false);
	pos += nbytes;

	show_prog_field("MemSize (bytes)", pos, nbytes, false);
	pos += nbytes;

	/* On 32bit, the flag field exists after the MemSize */
	if (!is64bit) {
		show_prog_flags(pos);
		pos += 4;
	}

	show_prog_field("Align", pos, nbytes, true);

	printf("\n");
}

static void show_program_headers()
{
	int ret;
	uint64_t i;

	/* return if the file does not contain a program header table */
	if (ph_off == 0)
		return;

	prog_header = malloc(ph_size);
	if (!prog_header)
		errx(1, "malloc prog_header");

	printf("Program Header Table\n");
	printf("====================\n");

	// seek to program header offset (it's not _needed_ but let's do it
	// anyway)
	lseek(fd, ph_off, SEEK_SET);

	for (i = 0; i < ph_num; i++) {
		/*
		 * after each read, the file position will be at the next
		 * program header
		 */
		ret = read(fd, prog_header, ph_size);
		if (ret == -1)
			errx(1, "prog header");
		show_prog_header();
	}

	free(prog_header);
}

static void show_section_header(struct sh_entry *entry)
{
	int nbytes = is64bit ? 8 : 4;
	int pos;

	entry->sh_name = get_section_field(0, 4);
	entry->sh_type = get_section_field(4, 4);

	pos = 8;
	entry->sh_flags = get_section_field(pos, nbytes);

	pos += nbytes;
	entry->sh_addr = get_section_field(pos, nbytes);

	pos += nbytes;
	entry->sh_offset = get_section_field(pos, nbytes);

	pos += nbytes;
	entry->sh_size = get_section_field(pos, nbytes);
}

static void show_section_headers()
{
	struct sh_entry entries[sh_num];
	uint64_t shstrtab_off;
	uint64_t shstrtab_size;
	unsigned char *shstrtab_data;
	size_t i;

	 /* return if the file does not contain a section header table */
	if (sh_off == 0)
		return;

	section_header = malloc(sh_size);
	if (!section_header)
		errx(1, "malloc section_header");

	printf("Section Header Table\n");
	printf("====================\n");

	/* Seek to the start of the section header table */
	lseek(fd, sh_off, SEEK_SET);

	/*
	 * Load the values of the section header into entries to print them
	 * later
	 */
	for (i = 0; i < sh_num; i++) {
		int ret = read(fd, section_header, sh_size);
		if (ret == -1)
			errx(1, "section header");
		show_section_header(&entries[i]);

		/*
		 * Store the segment pointed by the shstrtab segment headers.
		 * It will be needed later to get all the section header names.
		 */
		if (sh_strndx == i) {
			shstrtab_off = entries[i].sh_offset;
			shstrtab_size = entries[i].sh_size;
		}
	}

	shstrtab_data = malloc(shstrtab_size);
	if (!shstrtab_data)
		errx(1, "malloc shstrtab_data");

	pread(fd, shstrtab_data, shstrtab_size, shstrtab_off);

	/* Print section header data */
	for (i = 0; i < sh_num; i++) {
		printf("Section name: %s\n", shstrtab_data + entries[i].sh_name);
		printf("String name offset: %d\n", entries[i].sh_name);
		printf("Section offset: %d\n", entries[i].sh_offset);
		printf("Section Type: %d\n", entries[i].sh_type);
		printf("\n");
	}

	free(shstrtab_data);
	free(section_header);
}

int main(int argc, char **argv)
{
	if (argc != 2)
		err(1, "Usage: %s <elf file>\n", argv[0]);

	fd = open(argv[1], O_RDONLY);
	if (fd == -1)
		err(1, "%s", argv[1]);

	show_header_fields();
	show_program_headers();
	show_section_headers();

	close(fd);

	return 0;
}
