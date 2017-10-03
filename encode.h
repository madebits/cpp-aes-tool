#ifndef ENCODE_H
#define ENCODE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AES_ENCRYPT     0
#define AES_DECRYPT     1

#ifdef __cplusplus
extern "C" {
#endif

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
	int verbose,
	int deriveKeyMode
	);

#ifdef __cplusplus
}
#endif

#endif // ENCODE_H
