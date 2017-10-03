https://madebits.github.io/


gcc -std=c99 -o aes cript.c encode.c sha2.c aes.c pbkdf2.c



#32bit


gcc -m32 -o aes cript.c encode.c sha2.c aes.c pbkdf2.c


#64bit


gcc -m64 -o aes cript.c encode.c sha2.c aes.c pbkdf2.c



cl /Feaes cript.c encode.c sha2.c aes.c pbkdf2.c
