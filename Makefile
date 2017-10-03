CXX = gcc
CFLAGS = -std=c99 -Wall
SRC = program.c encode.c sha2.c aes.c pbkdf2.c stream.c

build: $(SRC)
	$(CXX) $(CFLAGS) -o aes $(SRC)

clean:
	rm aes

