#ifndef STREAM_H
#define STREAM_H

#ifdef __cplusplus
extern "C" {
#endif

#define BLOCK_LENGTH 16
#define STREAM_PAD_SIZE_MAX 2
#define STREAM_BUFFER_LENGTH ((STREAM_PAD_SIZE_MAX + 2) * BLOCK_LENGTH)
#define BSIZE(x) (size_t)((x) * sizeof(unsigned char))
#define BSIZE_BLOCK_LENGTH BSIZE(BLOCK_LENGTH)

typedef struct
{
    int rp;
    int last;
    int isLast;
    int padSize;
    int bufferSize;
    int encodeMode;
    unsigned char buffer[STREAM_BUFFER_LENGTH];
    int verbose;
} stream_ctx;

int stream_init(stream_ctx* ctx, int encodeMode, int padSize, int verbose);
int stream_read(stream_ctx* ctx, FILE* fin);
int stream_read_next(stream_ctx* ctx, FILE* fin, unsigned char output[]);
int stream_read_pad(stream_ctx* ctx, unsigned char output[]);
void dump(char* msg, unsigned char b[], int b_len, int verbose);

#ifdef __cplusplus
}
#endif

#endif /* STREAM_H */
