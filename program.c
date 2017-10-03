#include <time.h>
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include "encode.h"

const char* version = "1.1.2";
static void show_help()
{
    const char* help =
    "Usage: aes\n"
    "  [-i fileIn]\n"
    "  [-o fileOut]\n"
    "  -p password | -f passwordFile\n"
    "  [-e | -d]\n"
    "  [-k keySize]\n"
    "  [-c iterationCount]\n"
    "  [-r fileRandomIn]\n"
    "  [-a] [-m] [-s] [-v] [-?]\n"
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
    "                      at most 1024 first bytes are read from first line\n"
    "                      if -f - then stdin is used\n"
    "  -e                : encrypt mode (default)\n"
    "  -d                : decrypt mode\n"

    "  -c iterationCount : default 1000000, should be >= 1\n"
    "  -r fileRandomIn   : a file to read bytes of random data for IV, salt\n"
    "                      if not set or shorter than needed\n"
    "                      that the rest is filled with C rand() data\n"
    "                      on Linux use /dev/urandom as fileRandomIn (default)\n"
    "\n"
    "  -k keySize        : default 256, valid values are 128, 192, 256\n"
    "  -a                : do not use authenticated encryption (ae)\n"
    "                      default is to use authenticated encryption\n"
    "                      implies also -x\n"
    "  -m                : use PBKDF1 (SHA256) for key generation\n"
    "                      default is PBKDF2 (SHA256)\n"
    "                      ignored if -a is not set\n"
    "  -s                : if specified salt is 16 bytes, if not specified\n"
    "                      then salt as long as -k keySize (default)\n"
    "\n"
    "  -v                : verbose (stderr)\n"
    "  -?                : shows this help (stderr)\n"
    "\n"
    "Notes:\n"
    "- AES (FIPS 197), SHA256 (FIPS 180-2), PBKDF2 are from http://xyssl.org/\n"
    "\n"
    "Examples:\n"
    "- To encrypt: aes -i file.txt -o file.bin -p password\n"
    "- To decrypt: aes -d -i file.bin -o file.txt -p password\n";
    fprintf(stderr, "AES Tool: Version %s\n", version);
    fprintf(stderr, "%s", help);
    fprintf(stderr, "Maximum -c iteration count is %ld\n\n", LONG_MAX);
}

#define read_long(a) strtol((a), (char **)NULL, 10)
#define read_int(a) (int)strtol((a), (char **)NULL, 10)
#define skipped() if(ops.verbose) fprintf(stderr, "warning: skipped: %s\n", argv[i]);

int main(int argc, char *argv[])
{
    encode_ops ops;
    FILE* fin = 0;
    FILE* fout = 0;
    FILE* frnd = 0;
    FILE* fpass = 0;
    int i = 1;
    int error = 0;
    char* pass = 0;
    int pass_length = 0;
    char passBuffer[1025];
    int passBufferLength = 1024;
    int passBufferRead = 0;
    int pi = 0;

    ops.key_len = 32;
    ops.mode = AES_ENCRYPT;
    ops.salt_len_equals_keysize = 1;
    ops.iteration_count = 1000000L;
    ops.verbose = 0;
    ops.deriveKey1 = 0;
    ops.ae = 1;

    for(i = 1; i < argc; i++)
    {
        if(((argv[i][0] == '-') || (argv[i][0] == '/')) && (argv[i][2] == 0) )
        {
            switch(argv[i][1])
            {
                case '?':
                    show_help();
                    return 0;
                case 'v':
                    ops.verbose++;
                    break;
                case 's':
                    ops.salt_len_equals_keysize = 0;
                    break;
                case 'i':
                    if(!fin)
                    {
                        i++;
                        if(i >= argc)
                        {
                            fprintf(stderr, "error: -i input file not specified\n");
                            return 1;
                        }
                        fin = (strcmp(argv[i], "-") == 0) ? stdin : fopen(argv[i], "rb");
                        if(fin == 0)
                        {
                            fprintf(stderr, "error: -i input file not specified or cannot be read\n");
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
                            fprintf(stderr, "error: -o output file not specified\n");
                            return 1;
                        }
                        fout = (strcmp(argv[i], "-") == 0) ? stdout : fopen(argv[i], "wb");
                        if(fout == 0)
                        {
                            fprintf(stderr, "error: -o output file not specified or cannot be read\n");
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
                            fprintf(stderr, "error: -r random data file not specified\n");
                            return 1;
                        }
                        frnd = fopen(argv[i], "rb");
                        if(frnd == 0)
                        {
                            fprintf(stderr, "error: -r random data file not specified or cannot be read\n");
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
                            fprintf(stderr, "error: -p password not specified\n");
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
                            fprintf(stderr, "error: -f password file not specified\n");
                            return 1;
                        }
                        fpass = (strcmp(argv[i], "-") == 0) ? stdin : fopen(argv[i], "rb");
                        if(fpass == 0)
                        {
                            fprintf(stderr, "error: -f password file not specified or cannot be read\n");
                            return 1;
                        }
                        passBufferRead = (int)(fread(passBuffer, (size_t)1, passBufferLength * sizeof(char), fpass) / sizeof(char));
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
                        pass_length = (int)(strlen(pass) * sizeof(char));
                    }
                    else
                    {
                        skipped();
                    }
                    break;
                case 'e':
                    ops.mode = AES_ENCRYPT;
                    break;
                case 'd':
                    ops.mode = AES_DECRYPT;
                    break;
                case 'm':
                    ops.deriveKey1 = 1;
                    break;
                case 'a':
                    ops.ae = 0;
                    break;
                case 'k':
                    i++;
                    if(i >= argc)
                    {
                        fprintf(stderr, "error: -k size not specified\n");
                        return 1;
                    }
                    ops.key_len = read_int(argv[i]) / 8;
                    if((ops.key_len != 16) && (ops.key_len != 24) && (ops.key_len != 32))
                    {
                        fprintf(stderr, "error: -k keySize can be one of 128, 192, 256\n");
                        return 1;
                    }
                    break;
                case 'c':
                    i++;
                    if(i >= argc)
                    {
                        fprintf(stderr, "error: -c count not specified\n");
                        return 1;
                    }
                    ops.iteration_count = read_long(argv[i]);
                    break;
                default:
                    fprintf(stderr, "error: unknown argument: %s, use -? for help!\n", argv[i]);
                    return 1;
            }
        }
        else
        {
            fprintf(stderr, "error: unknown argument: %s, use -? for help!\n", argv[i]);
            return 1;
        }
    }

    if(ops.ae && ops.deriveKey1)
    {
        ops.deriveKey1 = 0;
        fprintf(stderr, "warning: using -m makes only sense if -a is also set and is ignored\n");
    }

    if(!fin) fin = stdin;
    if(!fout) fout = stdout;
    if(!pass || (pass_length <= 0))
    {
        fprintf(stderr, "error: -p password is required\n");
        return 1;
    }
    if(ops.iteration_count < 1L) ops.iteration_count = 1L;

    if(ops.verbose) fprintf(stderr,
        "\nAES START %s (CBC,SHA226): %s, keySize: %d bytes (%d bit), ae=%d, pass: [%s], PBKDF%d, iterationCount %ld ...\n",
        version,
        ops.mode == AES_ENCRYPT ? "ENCRYPT" : "DECRYPT",
        ops.key_len,
        ops.key_len * 8,
        ops.ae,
        pass,
        ops.deriveKey1 ? 1 : 2,
        ops.iteration_count);

    srand((unsigned)time(NULL));
    if((ops.mode == AES_ENCRYPT) && !frnd)
    {
        frnd = fopen("/dev/urandom", "rb");
        if(ops.verbose && (frnd != 0))
        {
            fprintf(stderr, "using -r /dev/urandom\n");
        }
    }

    error = encode(fin, fout, (unsigned char*)pass, pass_length, frnd, &ops);
    memset(pass, 0, pass_length * sizeof(char));
    if(fout && (fflush(fout) == EOF))
    {
        error = 1;
    }

    if(ops.verbose || error)
    {
        fprintf(stderr, "\n%s (%d) (%s)\n", !error ? "DONE" : "FAILED", error, ops.mode == AES_ENCRYPT ? "encrypt" : "decrypt");
    }

    memset(&ops, 0, sizeof(encode_ops));

    if(fin && (fin != stdin)) fclose(fin);
    if(fout && (fout != stdout)) fclose(fout);
    if(frnd && (frnd != stdin)) fclose(frnd);

    return error;
}


