#ifndef PBK_H
#define PBK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void derive_key(
	int mode,
	unsigned char key[],
	int key_len, /** in bytes */
	unsigned char password[],
	int password_len,
	unsigned char salt[],
	int salt_len,
	long iteration_count
	);

#ifdef __cplusplus
}
#endif

#endif //PBK_H
