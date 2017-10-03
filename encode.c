#include "encode.h"
#include "xyssl/aes.h"
#include "pbkdf2.h"
#include "xyssl/sha2.h"
#include "stream.h"

#ifndef BLOCK_LEN
#define BLOCK_LEN 16
#endif

#define AE_BLOCK_LEN 32
#define KEY_LEN_MAX 32

/** well, salt, iv only need to be different for each run */
static void fill_random(unsigned char b[], int b_len, FILE* frnd, int verbose)
{
    int i = 0;

    if(frnd)
    {
        i = (int)(fread(b, (size_t)1, BSIZE(b_len), frnd) / sizeof(unsigned char));
        if(verbose) fprintf(stderr, "Read %d of %d random bytes from -r file\n", i, b_len);
        if(i == b_len)
        {
            return;
        }
    }

    if(verbose) fprintf(stderr, "Using %d of %d random bytes from rand() - weak!!!\n", b_len - i, b_len);
    for(; i <  b_len; i++)
    {
        b[i] = rand() % 256;
    }
}

/** return 0 on success, CBC mode */
int encode(
    FILE* fin,
    FILE* fout,
    unsigned char password[],
    int password_len,
    FILE* frnd,
    encode_ops* ops
    )
{
    sha2_context h_ctx;
    aes_context ctx;
    unsigned char key[KEY_LEN_MAX];
    int key_bits = ops->key_len * 8;
    unsigned char salt[KEY_LEN_MAX];
    int salt_len = 16;
    unsigned char iv[BLOCK_LEN];
    unsigned char input[BLOCK_LEN];
    unsigned char output[BLOCK_LEN]; /** used initially as iv */
    int read_res = 0;
    int last_block = 0;
    int i = 0;
    stream_ctx stream;
    int len = 0;

    unsigned char ae_salt[AE_BLOCK_LEN];
    unsigned char ae_block[AE_BLOCK_LEN];
    unsigned char ae_block_pad[AE_BLOCK_LEN];

    if(!fin || !fout) return 1;
    if((key_bits != 128) && (key_bits != 192) && (key_bits != 256))
    {
        return 1;
    }
    if(password_len <= 0) return 1;
    if(ops->salt_len_equals_keysize)
    {
        salt_len = ops->key_len;
    }

    memset(key, 0, BSIZE(KEY_LEN_MAX));
    memset(salt, 0, BSIZE(salt_len));
    memset(input, 0, BSIZE_BLOCK_LENGTH);
    memset(output, 0, BSIZE_BLOCK_LENGTH);

    memset(ae_salt, 0, BSIZE(AE_BLOCK_LEN));
    memset(ae_block, 0, BSIZE(AE_BLOCK_LEN));
    memset(ae_block_pad, 0, BSIZE(AE_BLOCK_LEN));

    switch(ops->mode)
    {
    case AES_ENCRYPT:
        fill_random(output, BLOCK_LEN, frnd, ops->verbose);
        dump("iv   (encrypt)", output, BLOCK_LEN, ops->verbose);
        fill_random(salt, salt_len, frnd, ops->verbose);
        dump("salt (encrypt)", salt, salt_len, ops->verbose);
        derive_key(ops->deriveKey1, key, ops->key_len, password, password_len, salt, salt_len, ops->iteration_count);
        aes_setkey_enc(&ctx, key, key_bits);
        memset(key, 0, BSIZE(KEY_LEN_MAX));
        if(ops->ae)
        {
            fill_random(ae_salt, AE_BLOCK_LEN, frnd, ops->verbose);
            dump("ae: salt (encrypt)", ae_salt, AE_BLOCK_LEN, ops->verbose);
            derive_key(0, ae_block, AE_BLOCK_LEN, password, password_len, ae_salt, AE_BLOCK_LEN, ops->iteration_count);
            sha2_hmac_starts(&h_ctx, ae_block, AE_BLOCK_LEN, 0);
            sha2_hmac_update(&h_ctx, ae_salt, AE_BLOCK_LEN);
        }

        /* write header - looks random */
        if(fwrite(output, (size_t)1, BSIZE_BLOCK_LENGTH, fout) != BSIZE_BLOCK_LENGTH) return 1;
        if(fwrite(salt, (size_t)1, BSIZE(salt_len), fout) != BSIZE(salt_len)) return 1;
        if(ops->ae)
        {
            memcpy(iv, output, BSIZE_BLOCK_LENGTH);
            aes_crypt_cbc(&ctx, ops->mode, BLOCK_LEN, iv, &ae_salt[0], output);
            if(fwrite(output, (size_t)1, BSIZE_BLOCK_LENGTH, fout) != BSIZE_BLOCK_LENGTH) return 1;

            memcpy(iv, output, BSIZE_BLOCK_LENGTH);
            aes_crypt_cbc(&ctx, ops->mode, BLOCK_LEN, iv, &ae_salt[0 + BLOCK_LEN], output);
            if(fwrite(output, (size_t)1, BSIZE_BLOCK_LENGTH, fout) != BSIZE_BLOCK_LENGTH) return 1;
        }

        break;
    case AES_DECRYPT:
        /* read header */
        if(fread(output, (size_t)1, BSIZE_BLOCK_LENGTH, fin) != BSIZE_BLOCK_LENGTH) return 1;
        if(fread(salt, (size_t)1, BSIZE(salt_len), fin) != BSIZE(salt_len)) return 1;
        dump("iv   (decrypt)", output, BLOCK_LEN, ops->verbose);
        dump("salt (decrypt)", salt, salt_len, ops->verbose);
        memcpy(iv, output, BSIZE_BLOCK_LENGTH);
        derive_key(ops->deriveKey1, key, ops->key_len, password, password_len, salt, salt_len, ops->iteration_count);
        aes_setkey_dec(&ctx, key, key_bits);
        memset(key, 0, BSIZE(KEY_LEN_MAX));

        if(ops->ae)
        {
            if(fread(input, (size_t)1, BSIZE_BLOCK_LENGTH, fin) != BSIZE_BLOCK_LENGTH) return 1;
            aes_crypt_cbc(&ctx, ops->mode, BLOCK_LEN, iv, input, output);
            memcpy(iv, input, BSIZE_BLOCK_LENGTH);
            memcpy(&ae_salt[0], output, BSIZE_BLOCK_LENGTH);

            if(fread(input, (size_t)1, BSIZE_BLOCK_LENGTH, fin) != BSIZE_BLOCK_LENGTH) return 1;
            aes_crypt_cbc(&ctx, ops->mode, BLOCK_LEN, iv, input, output);
            memcpy(iv, input, BSIZE_BLOCK_LENGTH);
            memcpy(&ae_salt[0+ BLOCK_LEN], output, BSIZE_BLOCK_LENGTH);

            dump("ae: salt (decrypt)", ae_salt, AE_BLOCK_LEN, ops->verbose);
            derive_key(0, ae_block, AE_BLOCK_LEN, password, password_len, ae_salt, AE_BLOCK_LEN, ops->iteration_count);
            sha2_hmac_starts(&h_ctx, ae_block, AE_BLOCK_LEN, 0);
            sha2_hmac_update(&h_ctx, ae_salt, AE_BLOCK_LEN);
        }

        break;
    default:
        return 1;
    }

    stream_init(&stream, ops->mode == AES_ENCRYPT ? 1 : 0, ops->ae ? 2 : 0, ops->verbose);

    while(1)
    {
        if(last_block)
        {
            break;
        }
        read_res = stream_read_next(&stream, fin, input);
        if(read_res < 0)
        {
            return 1;
        }
        last_block = (read_res == 1);

        /* ae: update with input */
        if((ops->mode == AES_ENCRYPT) && ops->ae)
        {
            sha2_hmac_update(&h_ctx, input, BLOCK_LEN);
        }

        if(ops->verbose > 1) dump(ops->mode == AES_ENCRYPT ? "in  (encrypt)" : "in  (decrypt)", input, BLOCK_LEN, ops->verbose);

        /* convert block */
        if(ops->mode == AES_ENCRYPT)
        {
            memcpy(iv, output, BSIZE_BLOCK_LENGTH);
        }
        aes_crypt_cbc(&ctx, ops->mode, BLOCK_LEN, iv, input, output);
        if(ops->mode == AES_DECRYPT)
        {
            memcpy(iv, input, BSIZE_BLOCK_LENGTH);
        }

        if(ops->verbose > 1) dump(ops->mode == AES_ENCRYPT ? "out (encrypt)" : "out (decrypt)", output, BLOCK_LEN, ops->verbose);

        /* ae: update with output */
        if((ops->mode == AES_DECRYPT) && ops->ae)
        {
            sha2_hmac_update(&h_ctx, output, BLOCK_LEN);
        }

        if((ops->mode == AES_DECRYPT) && (last_block && (output[BLOCK_LEN - 1] < BLOCK_LEN)))
        {
            len = BLOCK_LEN - output[BLOCK_LEN - 1];
            if(fwrite(&output[0], 1, len, fout) != len) return 1;
        }
        else
        {
            if(fwrite(&output[0], (size_t)1, BSIZE_BLOCK_LENGTH, fout) != BSIZE_BLOCK_LENGTH) return 1;
        }
    }

    if((ops->mode == AES_ENCRYPT) && ops->ae)
    {
        sha2_hmac_finish(&h_ctx, ae_block);
        dump("ae: data (encrypt)", ae_block, AE_BLOCK_LEN, ops->verbose);

        memcpy(iv, output, BSIZE_BLOCK_LENGTH);
        aes_crypt_cbc(&ctx, ops->mode, BLOCK_LEN, iv, &ae_block[0], output);
        if(fwrite(output, (size_t)1, BSIZE_BLOCK_LENGTH, fout) != BSIZE_BLOCK_LENGTH) return 1;

        memcpy(iv, output, BSIZE_BLOCK_LENGTH);
        aes_crypt_cbc(&ctx, ops->mode, BLOCK_LEN, iv, &ae_block[0 + BLOCK_LEN], output);
        if(fwrite(output, (size_t)1, BSIZE_BLOCK_LENGTH, fout) != BSIZE_BLOCK_LENGTH) return 1;
    }
    if((ops->mode == AES_DECRYPT) && ops->ae)
    {
        sha2_hmac_finish(&h_ctx, ae_block);
        dump("ae: data (decrypt)", ae_block, AE_BLOCK_LEN, ops->verbose);
        stream_read_pad(&stream, ae_block_pad);

        aes_crypt_cbc(&ctx, ops->mode, BLOCK_LEN, iv, &ae_block_pad[0], output);
        memcpy(iv, &ae_block_pad[0], BSIZE_BLOCK_LENGTH);
        memcpy(&ae_block_pad[0], output, BSIZE_BLOCK_LENGTH);

        aes_crypt_cbc(&ctx, ops->mode, BLOCK_LEN, iv, &ae_block_pad[0 + BLOCK_LEN], output);
        /* memcpy(iv, &ae_block_pad[0 + BLOCK_LEN], BSIZE_BLOCK_LENGTH); */
        memcpy(&ae_block_pad[0 + BLOCK_LEN], output, BSIZE_BLOCK_LENGTH);

        dump("ae: pad  (decrypt)", ae_block_pad, AE_BLOCK_LEN, ops->verbose);
        for(i = 0; i < AE_BLOCK_LEN; i++)
        {
            if(ae_block[i] != ae_block_pad[i])
            {
                fprintf(stderr, "error: ae check failed\n");
                return 1;
            }
        }
    }

    memset(&h_ctx, 0, sizeof(sha2_context));
    memset(&ctx, 0, sizeof(aes_context));
    memset(&stream, 0, sizeof(stream_ctx));

    memset(key, 0, BSIZE(KEY_LEN_MAX));
    memset(salt, 0, BSIZE(salt_len));
    memset(input, 0, BSIZE_BLOCK_LENGTH);
    memset(output, 0, BSIZE_BLOCK_LENGTH);

    memset(ae_salt, 0, BSIZE(AE_BLOCK_LEN));
    memset(ae_block, 0, BSIZE(AE_BLOCK_LEN));
    memset(ae_block_pad, 0, BSIZE(AE_BLOCK_LEN));

    return 0;
}
