all:
	gcc myreadelf.c -Wall -Wextra -Werror -o myreadelf
clean:
	rm -f myreadelf
