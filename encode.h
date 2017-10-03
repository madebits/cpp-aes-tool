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

typedef struct
{
    int mode;
    int key_len;
    int salt_len_equals_keysize;
    long iteration_count;
    int verbose;
    int deriveKey1;
    int ae; /* 0 or 1 */
} encode_ops;

/** return 0 on success, CBC mode */
int encode(
    FILE* fin,
    FILE* fout,
    unsigned char password[],
    int password_len,
    FILE* frnd,
    encode_ops* ops
    );

#ifdef __cplusplus
}
#endif

#endif // ENCODE_H
