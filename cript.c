#include "encode.h"
#include <time.h> // for srand
#include <stdlib.h>
#include <math.h>

static void show_help()
{
	const char* help = 
	"**********************************************\n"
	"* AES - Encrypt a file using AES in CBC mode *\n"
	"* Version 1.0.8                              *\n"
	"**********************************************\n"
	"\n"
	"Usage: aes\n"
	"  [-i fileIn]\n"
	"  [-o fileOut]\n"
	"  -p password\n"
	"  [-e | -d]\n"
	"  [-k keySize]\n"
	"  [-c iterationCount]\n"
	"  [-r fileRandomIn]\n"
	"  [-h startOffset]\n"
	"  [-a] [-s] [-v] [-?]\n"
	"\n"        
	"Where:\n"
	"  -i fileIn         : input file path\n"
	"                      fileIn (data) is not changed\n" 
	"                      if -i is not specified, or -i - then stdin\n"
	"                      is used\n"
	"  -o fileOut        : output file path\n"
	"                      if fileOut exists it will be overwritten,\n"
	"                      if -o is not specified, or -o - then stdout\n"
	"                      is used\n"
	"  -p password       : password (required or -f)\n"
	"  -f passwordFile   : read password from first file line (required or -p)\n"
	"                      at most 256 first bytes are read\n"
	"  -e                : encrypt mode (default)\n"
	"  -d                : decrypt mode\n"
	"  -k keySize        : default 256, valid values are 128, 192, 256\n"
	"  -c iterationCount : default 1024, should be >= 1\n"
	"  -r fileRandomIn   : a file to read bytes of random data used for\n"
	"                      IV, salt, and -h option; minimum length should\n"
	"                      be (48 + startOffset used for -h)\n"
	"                      if not set or shorter than (48 + startOffset)\n" 
	"                      that the rest is filled with C rand() data\n"
	"                      on Linux, use /dev/urandom as fileRandomIn\n"
	"  -h startOffset    : if specified, file is filled with random data\n"
	"                      up to this offset on encryption, or skipped\n"
	"                      from file start on decryption, default is 0\n"
	"  -a [level]        : if specified, then -c, -h values are auto\n"
	"                      calculated from password (-c, -h are ignored)\n"
	"                      If not specified level is 5, setting it to another\n"
	"                      value uses that power of 10 as start for -c\n"
	"  -s                : if specified salt is 16 bytes, if not specified\n"
	"                      then salt as long as -k keySize (default)\n"
	"  -v                : verbose (stderr)\n"
	"  -?                : shows this help (stderr)\n"
	"\n"
	"Notes:\n"
	"- Key generation based on PBKDF1 (PKCS #5 v1.5) with SHA256\n"
	"- AES (FIPS 197), SHA256 (FIPS 180-2) are from http://xyssl.org/\n"
	"\n"
	"Examples:\n"
	"- To encrypt: aes -i file.txt -o file.bin -p password\n"
	"- To decrypt: aes -d -i file.bin -o file.txt -p password\n";
	fprintf(stderr, "%s", help);
}

static int password_sum(const char password[], int password_length)
{
	int i = 0;
	int sum  = 0;
	for(; i < password_length; i++)
	{
		sum += (int)password[i];
	}
	return sum;
}

static long math_pow(long base, int power)
{
	int i = 2;
	long res = base;
	for(; i <= power; i++) 
	{
		res *= base;
	}
	return res;
}

#define read_long(a) strtol((a), (char **)NULL, 10)
#define read_int(a) (int)strtol((a), (char **)NULL, 10)
#define skipped() if(verbose) fprintf(stderr, "Warning: skipped: %s\n", argv[i]);

int main(int argc, char *argv[])
{
	FILE* fin = 0;
	FILE* fout = 0;
	FILE* frnd = 0;
	FILE* fpass = 0;
	int i = 1;
	int key_size = 32;
	long icount = 1024L;
	int mode = AES_ENCRYPT;
	int error = 0;
	int verbose = 0;
	char* pass = 0;
	int pass_length = 0;
	int start_offset = 0;
	int auto_ch  = 0;
	int pass_sum = 0;
	int salt_len_equals_keysize = 1;
	char passBuffer[257];
	int passBufferLength = 256;
	int passBufferRead = 0;
	int pi = 0;
	
	for(; i < argc; i++)
	{
		if(((argv[i][0] == '-') || (argv[i][0] == '/')) && (argv[i][2] == 0) )
		{
			switch(argv[i][1])
			{
				case '?':
					show_help();
					return 0;
				case 'v':
					verbose = 1;
					break;
				case 's':
					salt_len_equals_keysize = 0;
					break;
				case 'i':
					if(!fin) 
					{	
						i++;
						if(i >= argc)
						{
							fprintf(stderr, "Error: -i input file not specified\n"); 
							return 1;
						}
						fin = (strcmp(argv[i], "-") == 0) ? stdin : fopen(argv[i], "rb");
						if(fin == 0)
						{
							fprintf(stderr, "Error: -i input file not specified or cannot be read\n"); 
							return 1;
						}
					}
					else
					{
						skipped();
					}
					break;
				case 'o':
					if(!fout) 
					{
						i++;
						if(i >= argc)
						{
							fprintf(stderr, "Error: -o output file not specified\n"); 
							return 1;
						}
						fout = (strcmp(argv[i], "-") == 0) ? stdout : fopen(argv[i], "wb");
						if(fout == 0)
						{
							fprintf(stderr, "Error: -o output file not specified or cannot be read\n"); 
							return 1;
						}
					}
					else
					{
						skipped();
					}
					break;
				case 'r':
					if(!frnd) 
					{	
						i++;
						if(i >= argc)
						{
							fprintf(stderr, "Error: -r random data file not specified\n"); 
							return 1;
						}
						frnd = fopen(argv[i], "rb");
						if(frnd == 0)
						{
							fprintf(stderr, "Error: -r random data file not specified or cannot be read\n"); 
							return 1;
						}
					}
					else
					{
						skipped();
					}
					break;
				case 'p':
					if(!pass) 
					{
						i++;
						if(i >= argc)
						{
							fprintf(stderr, "Error: -p password not specified\n"); 
							return 1;
						}
						pass = argv[i];
						pass_length = (int)strlen(pass);
					}
					else
					{
						skipped();
					}
					break;
				case 'f':
					if(!fpass) 
					{	
						i++;
						if(i >= argc)
						{
							fprintf(stderr, "Error: -f password file not specified\n"); 
							return 1;
						}
						fpass = (strcmp(argv[i], "-") == 0) ? stdin : fopen(argv[i], "rb");
						if(fpass == 0)
						{
							fprintf(stderr, "Error: -f password file not specified or cannot be read\n"); 
							return 1;
						}
						passBufferRead = fread(&passBuffer[0], 1, passBufferLength * sizeof(char), fpass);
						fclose(fpass);
						passBuffer[passBufferRead] = '\0';
						passBuffer[passBufferLength + 1] = '\0';
						for(pi = 0; pi < passBufferRead; pi++)
						{
							switch(passBuffer[pi])
							{
								case '\r':
								case '\n':
									passBuffer[pi] = '\0';
									break;
							}
						}
						pass = passBuffer;
						pass_length = (int)strlen(pass);
					}
					else
					{
						skipped();
					}
					break;
				case 'e':
					mode = AES_ENCRYPT;
					break;
				case 'd':
					mode = AES_DECRYPT;
					break;
				case 'k':
				    i++;
					if(i >= argc)
					{
						fprintf(stderr, "Error: -k size not specified\n"); 
						return 1;
					}
					key_size = read_int(argv[i]) / 8;
					if((key_size != 16) && (key_size != 24) && (key_size != 32))
					{
						fprintf(stderr, "Error: -k keySize can be one of 128, 192, 256\n");
						return 1;
					}
					break;
				case 'c':
				    i++;
					if(i >= argc)
					{
						fprintf(stderr, "Error: -c count not specified\n"); 
						return 1;
					}
					icount = read_long(argv[i]);
					break;
				case 'h':
					i++;
					if(i >= argc)
					{
						fprintf(stderr, "Error: -h offset not specified\n"); 
						return 1;
					}
					start_offset = read_int(argv[i]);
					break;
				case 'a':
					auto_ch = 5;
					if(((i + 1) < argc) && (argv[i + 1][0] != '-'))
					{
						auto_ch = read_int(argv[++i]);
						if(auto_ch <= 0) auto_ch = 5;
					}
					break;
				default:
					fprintf(stderr, "Error: unknown argument: %s. Use -? for help!\n", argv[i]);
					return 1;
			}
		}
		else
		{
			fprintf(stderr, "Error: unknown argument: %s. Use -? for help!\n", argv[i]);
			return 1;
		}
	}

	if(!fin) fin = stdin;
	if(!fout) fout = stdout;
	if(!pass || (pass_length <= 0))
	{
		fprintf(stderr, "Error: -p password is required\n");
		return 1; 
	}
	if(icount < 1L) icount = 1L;
	if(auto_ch > 0)
	{
		pass_sum = password_sum(pass, pass_length);
		start_offset = (pass_sum % 512) + 1;
		icount = math_pow(10L, auto_ch) + (auto_ch * (pass_sum % 1024));
	}
	
	if(verbose) fprintf(stderr, "| %s with key size %d bytes (%d bit) [IterationCount %ld] [RandomOffset %d] ...\n", 
		mode == AES_ENCRYPT ? "Encrypting" : "Decrypting", 
		key_size,
		key_size * 8,
		icount,
		start_offset);

	srand((unsigned)time(NULL));
	error = encode(fin, fout, mode, key_size, (unsigned char*)pass, pass_length, icount, salt_len_equals_keysize, frnd, start_offset, verbose);
	memset(pass, 0, pass_length * sizeof(char));
	
	if(verbose) fprintf(stderr, "%s (%d)\n", !error ? "| Done!" : "| Failed!", error);
	if(fin && (fin != stdin)) fclose(fin);
	if(fout && (fout != stdout)) fclose(fout);
	if(frnd && (frnd != stdin)) fclose(frnd);

	return error;
}


