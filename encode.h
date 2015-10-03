#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AES_ENCRYPT     0
#define AES_DECRYPT     1

/** return 0 on success, CBC mode */
int encode(
	FILE* fin,
	FILE* fout,
	int mode,
	int keyLen,
	unsigned char password[],
	int password_len,
	long iteration_count,
	int salt_len_equals_keysize,
	FILE* frnd,
	int startOffset,
	int verbose
	);

/** encode calls this function internally */
void derive_key(
	unsigned char key[],
	int key_len, /** in bytes */
	unsigned char password[],
	int password_len,
	unsigned char salt[],
	int salt_len,
	long iteration_count
	);
