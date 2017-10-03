#include "pbkdf2.h"
#include "xyssl/sha2.h"

#define MBEDTLS_MD_MAX_SIZE 32

// https://github.com/ARMmbed/mbedtls/blob/master/library/pkcs5.c#L218
// adapted code
static void pbkdf2_hmac(unsigned char *password, int plen,
                unsigned char *salt, int slen,
                long iteration_count,
                int key_length,
                unsigned char *output)
{
    sha2_context ctx;
    int j;
    long i = 0L;
    unsigned char md1[MBEDTLS_MD_MAX_SIZE];
    unsigned char work[MBEDTLS_MD_MAX_SIZE];
    int md_size = MBEDTLS_MD_MAX_SIZE;
    int use_len = 0;
    unsigned char *out_p = output;
    unsigned char counter[4];

    memset( counter, 0, 4 * sizeof(unsigned char));
    counter[3] = 1;

    while( key_length )
    {
        // U1 ends up in work
        //
        sha2_hmac_starts( &ctx, password, plen, 0 );
        sha2_hmac_update( &ctx, salt, slen );
        sha2_hmac_update( &ctx, counter, 4 );
        sha2_hmac_finish( &ctx, work );

        memcpy( md1, work, md_size * sizeof(unsigned char) );

        for( i = 1; i < iteration_count; i++ )
        {
            // U2 ends up in md1
            //
            sha2_hmac_starts( &ctx, password, plen, 0 );
            sha2_hmac_update( &ctx, md1, md_size );
            sha2_hmac_finish( &ctx, md1 );

            // U1 xor U2
            //
            for( j = 0; j < md_size; j++ )
                work[j] ^= md1[j];
        }

        use_len = ( key_length < md_size ) ? key_length : md_size;
        memcpy( out_p, work, use_len * sizeof(unsigned char) );

        key_length -= use_len;
        out_p += use_len;

        for( i = 4; i > 0; i-- )
            if( ++counter[i - 1] != 0 )
                break;
    }

}

////////////////////////////////////////////////////////////////////////

/** PBKDF1 (PKCS #5 v1.5) */
static void derive_key_1(
    unsigned char key[],
    int key_len, /** in bytes */
    unsigned char password[],
    int password_len,
    unsigned char salt[],
    int salt_len,
    long iteration_count
    )
{
    sha2_context ctx;
    unsigned char output[32];
    long i = 0L;

    if(key_len > 32) key_len = 32;
    if(iteration_count < 0) iteration_count = 1024L;

    // first iteration, input = password + salt
    memset(&ctx, 0, sizeof(sha2_context));
    sha2_starts(&ctx, 0);
    sha2_update(&ctx, &password[0], password_len);
    memset(&password[0], 0, password_len * sizeof(unsigned char));

    if(salt_len > 0)
    {
        sha2_update(&ctx, &salt[0], salt_len);
    }
    sha2_finish(&ctx, &output[0]);

    // other iterations
    for(i = 1; i < iteration_count; i++)
    {
        memset(&ctx, 0, sizeof(sha2_context));
        sha2_starts(&ctx, 0);
        sha2_update(&ctx, &output[0], 32);
        sha2_finish(&ctx, &output[0]);
    }

    // done, copy key bytes
    memcpy(&key[0], &output[0], key_len * sizeof(unsigned char));
}

////////////////////////////////////////////////////////////////////////

void derive_key(
    int use1,
    unsigned char key[],
    int key_len, /** in bytes */
    unsigned char password[],
    int password_len,
    unsigned char salt[],
    int salt_len,
    long iteration_count
    )
{
    if(use1)
    {
        derive_key_1(&key[0], key_len, &password[0], password_len, &salt[0], salt_len, iteration_count);
    }
    else
    {
        pbkdf2_hmac(&password[0], password_len, &salt[0], salt_len, iteration_count, key_len, &key[0]);
    }
}

////////////////////////////////////////////////////////////////////////
