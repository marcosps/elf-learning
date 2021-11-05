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
static unsigned char elf_header[64];
static uint64_t ph_off;
static uint64_t ph_size;
static uint64_t ph_num;
static bool is64bit = false;

static unsigned char *prog_header;

static char* prog_type[] = {
	"",
	"LOAD",
};


/* Prints the entry point, ph offset and sh offset */
static uint64_t show_var_fields(char *msg, unsigned char *buf, size_t offset,
				size_t nbytes, bool hex, bool print)
{
	unsigned char data[9] = {0};
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

static uint64_t get_prog_field(size_t offset, size_t nbytes, bool hex)
{
	return show_var_fields("", prog_header, offset, nbytes, hex, false);
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
		ret = read(fd, elf_header + 52, 8);
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
	show_var_field("Section header offset (bytes)", pos, nbytes, false);

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
	show_var_field("Size of section headers (bytes)", pos, 2, false);

	// TODO: these two fields are zeroed
	// e_shnum
	pos += 2;
	show_var_field("Number of section headers", pos, 2, false);

	// e_shstrndx
	pos += 2;
	show_var_field("Section header string table index", pos, 2, false);

	printf("\n");
}

static void show_prog_flags(int pos)
{
	uint64_t flags;
	// p_flags
	flags = get_prog_field(pos, 4, true);
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
	type = get_prog_field(pos, 4, false);
	printf("Type: %s\n", prog_type[type]);
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

int main(int argc, char **argv)
{
	if (argc != 2)
		err(1, "Usage: %s <elf file>\n", argv[0]);

	fd = open(argv[1], O_RDONLY);
	if (fd == -1)
		err(1, "%s", argv[1]);

	show_header_fields();
	show_program_headers();

	close(fd);

	return 0;
}
