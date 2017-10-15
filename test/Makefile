CC=gcc
CFLAGS=-O2

all: test

test: test.c
	$(CC) $(CFLAGS) test.c -o test -L../build -lpoke

clean:
	@rm test
