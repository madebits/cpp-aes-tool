CXX = gcc
CFLAGS = -std=c99
SRC = cript.c encode.c sha2.c aes.c pbkdf2.c stream.c

build: $(SRC)
	$(CXX) $(CFLAGS) -o aes $(SRC)

clean:
	rm aes

