https://madebits.github.io/


gcc -std=c99 -o aes program.c encode.c sha2.c aes.c pbkdf2.c stream.c



#32bit


gcc -m32 -o aes program.c encode.c sha2.c aes.c pbkdf2.c stream.c


#64bit


gcc -m64 -o aes program.c encode.c sha2.c aes.c pbkdf2.c stream.c



cl /Feaes program.c encode.c sha2.c aes.c pbkdf2.c stream.c
