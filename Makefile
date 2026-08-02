CFLAGS=-I. -Os -g

all: sha3256 sha3512

check: kat
	./kat

clobber: clean
	rm -f sha3256 sha3512 kat

clean:
	rm -f sha3256.o sha3512.o

sha3256: test/main256.c sha3256.o
	$(CC) $(CFLAGS) -o sha3256 test/main256.c sha3256.o

sha3256.o: sha3256.c sha3256.h
	$(CC) $(CFLAGS) -c sha3256.c

sha3512: test/main512.c sha3512.o
	$(CC) $(CFLAGS) -o sha3512 test/main512.c sha3512.o

sha3512.o: sha3512.c sha3512.h
	$(CC) $(CFLAGS) -c sha3512.c

kat: test/kat.c sha3256.o sha3512.o
	$(CC) $(CFLAGS) -o kat test/kat.c sha3256.o sha3512.o
