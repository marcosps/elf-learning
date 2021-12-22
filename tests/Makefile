all:
	nasm -felf64 hello.asm
	ld hello.o -o hello
	nasm -felf64 -g symbols.asm
	nasm -felf64 -g executable_object.asm
	ld -g symbols.o executable_object.o -o main
clean:
	rm -f main symbols.o executable_object.o hello.o hello
