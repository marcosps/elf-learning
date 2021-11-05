all:
	nasm -felf64 hello.asm
	ld hello.o -o hello
	gcc myreadelf.c -Wall -Wextra -Werror -o myreadelf

clean:
	rm -f hello.o hello myreadelf
