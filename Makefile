CC=clang
CFLAGS=-Wall -Wextra -g

myreadelf: myreadelf.o
myreadelf.o: myreadelf.c

clean:
	rm myreadelf myreadelf.o
