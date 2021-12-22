all:
	nasm -felf64 -o main.o main.asm
	nasm -felf64 -o libso.o libso.asm
	ld -shared -o libso.so libso.o
	ld -o main main.o -d /home/mpdesouza/git/elf-learning/dso/libso.so  --dynamic-linker=/lib64/ld-linux-x86-64.so.2

clean:
	rm main.o main libso.so libso.o
