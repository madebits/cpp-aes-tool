#include "encode.h"
#include "xyssl/aes.h"
#include "pbkdf2.h"

/** well, salt, iv only need to be different for each run */
static void fill_random(unsigned char b[], int b_len, FILE* frnd, int verbose)
{
	int i = 0;

	if(frnd)
	{
		i = fread(&b[0], 1,  b_len, frnd);
	}

	if(verbose) fprintf(stderr, "| Read %d of %d random bytes from file\n", i, b_len);

	for(; i <  b_len; i++)
	{
		b[i] = rand() % 256;
	}
}

static int write_random_data(FILE* fout, int start_offset, FILE* frnd, int verbose)
{
	int i = 0;
	unsigned char buffer[512];
	int buffer_len = 512;
	int full_blocks = 0;
	int remainder = 0;

	if(start_offset <= 0) return 0;
	full_blocks = start_offset / buffer_len;
	remainder = start_offset % buffer_len;

	for(; i < full_blocks; i++)
	{
		fill_random(&buffer[0], buffer_len, frnd, verbose);
		if(fwrite(&buffer[0], 1, buffer_len, fout) != buffer_len) return 1;
	}

	if(remainder > 0)
	{
		fill_random(&buffer[0], remainder, frnd, verbose);
		if(fwrite(&buffer[0], 1, remainder, fout) != remainder) return 1;
	}

	return 0;
}

static int read_to_offset(FILE* fin, int start_offset)
{
	int i = 0;
	unsigned char buffer[512];
	int buffer_len = 512;
	int full_blocks = 0;
	int remainder = 0;

	if(start_offset <= 0) return 0;
	full_blocks = start_offset / buffer_len;
	remainder = start_offset % buffer_len;

	for(; i < full_blocks; i++)
	{
		if(fread(&buffer[0], 1, buffer_len, fin) != buffer_len) return 1;
	}

	if(remainder > 0)
	{
		if(fread(&buffer[0], 1, remainder, fin) != remainder) return 1;
	}
	
	return 0;
}

// ms-help://MS.VSCC/MS.MSDNVS/security/aboutcrypto_8jjb.htm
// (PKCS), PKCS #5, section 6.2
void pad_block(unsigned char b[], int b_len, int block_len)
{
	int pad = block_len - b_len;
	if(pad <= 0) return;
	memset(&b[b_len], pad, pad);
}

/** return 0 on success, CBC mode */
int encode(
	FILE* fin,
	FILE* fout,
	int mode,
	int key_len,
	unsigned char password[],
	int password_len,
	long iteration_count,
	int salt_len_equals_keysize,
	FILE* frnd,
	int start_offset,
	int verbose,
	int deriveKeyMode
	)
{
	aes_context ctx;
	unsigned char key[32];
	int key_bits = key_len * 8;
	unsigned char salt[32];
	int salt_len = 16;
	int block_len = 16;
	unsigned char iv[16];
	unsigned char input[16];
	unsigned char output[16]; /** used initially as iv */
	size_t read_count = 0;
	int last_block = 0;
	int can_read = 1;

	if(!fin || !fout) return 1;
	if((key_bits != 128) && (key_bits != 192) && (key_bits != 256))
	{
		return 1;
	}
	if(password_len <= 0) return 1;
	if(salt_len_equals_keysize)
	{
		salt_len = key_len;
	}
	if(verbose) fprintf(stderr, "| Salt length %d bytes\n", salt_len);
	
	memset(key, 0, 32 * sizeof(unsigned char));
	memset(salt, 0, salt_len * sizeof(unsigned char));
	memset(input, 0, block_len * sizeof(unsigned char));
	memset(output, 0, block_len * sizeof(unsigned char));

	// header
	switch(mode)
	{
	case AES_ENCRYPT:
		fill_random(&output[0], block_len, frnd, verbose);
		fill_random(&salt[0], salt_len, frnd, verbose);
		derive_key(deriveKeyMode, key, key_len, password, password_len, salt, salt_len, iteration_count);
		aes_setkey_enc(&ctx, key, key_bits);
		memset(key, 0, 32 * sizeof(unsigned char));
		if(write_random_data(fout, start_offset, frnd, verbose) != 0) return 1;
		if(fwrite(&output[0], 1, block_len, fout) != block_len) return 1;
		if(fwrite(&salt[0], 1, salt_len, fout) != salt_len) return 1;
		break;
	case AES_DECRYPT:
		if(start_offset > 0)
		{
			if(read_to_offset(fin, start_offset) != 0) return 1;
		}
		if(fread(&output[0], 1, block_len, fin) != block_len) return 1;
		if(fread(&salt[0], 1, salt_len, fin) != salt_len) return 1;
		memcpy(&iv[0], &output[0], block_len * sizeof(unsigned char));
		derive_key(deriveKeyMode, key, key_len, password, password_len, salt, salt_len, iteration_count);
		aes_setkey_dec(&ctx, key, key_bits);
		memset(key, 0, 32 * sizeof(unsigned char));
		break;
	default:
		return 1;
	}

	// rest
	while(1)
	{
		if(can_read)
		{
			read_count = fread(&input[0], 1, block_len, fin);
		}
		
		if(read_count <= 0)
		{
			break;
		}

		if(read_count < (size_t)block_len)
		{
			switch(mode)
			{
			case AES_ENCRYPT:
				pad_block(&input[0], (int)read_count, block_len);
				break;
			case AES_DECRYPT:
				return 1; // error
			}
		}

		if(mode == AES_ENCRYPT)
		{
			memcpy(&iv[0], &output[0], block_len * sizeof(unsigned char));
		}
		
		aes_crypt_cbc(&ctx, mode, block_len, &iv[0], &input[0], &output[0]);

		if(mode == AES_DECRYPT)
		{
			memcpy(&iv[0], &input[0], block_len * sizeof(unsigned char));
		}

		if(mode == AES_DECRYPT)
		{
			read_count = fread(&input[0], 1, block_len, fin);
			if(read_count < (size_t)block_len)
			{
				last_block = 1;
			}
			can_read = 0;
		}

		if(last_block)
		{
			if(output[block_len - 1] < block_len)
			{
				int len = block_len - output[block_len - 1];
				if(fwrite(&output[0], 1, len, fout) != len) return 1;
			}
			else
			{
				if(fwrite(&output[0], 1, block_len, fout) != block_len) return 1;
			}
			break;
		}

		if(fwrite(&output[0], 1, block_len, fout) != block_len) return 1;
	}

	memset(&ctx, 0, sizeof(aes_context));
	return 0;
}
