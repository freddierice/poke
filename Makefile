CC=gcc
CFLAGS=-Wall -fPIC -O2 

OBJS=build/poke.o

all: build build/libpoke.a build/libpoke.so
build:
	@mkdir build

build/poke.o: poke.c poke.h 
	$(CC) $(CFLAGS) -c -o $@ poke.c

build/libpoke.a: $(OBJS)
	ar rcs $@ $^

build/libpoke.so: $(OBJS)
	$(CC) -shared -o $@ $^

install: all
	@install -m 0755 build/libpoke.so /usr/lib 
	@install -m 0644 build/libpoke.a /usr/lib
	@install -m 0644 poke.h /usr/include

clean:
	@rm -rf build
