#ifndef STREAM_H
#define STREAM_H

#define BLOCK_LENGTH 16
#define PAD_SIZE_MAX 2
#define BUFFER_LENGTH ((PAD_SIZE_MAX + 2) * BLOCK_LENGTH)

typedef struct
{
    int rp;
    int last;
    int isLast;
    int padSize;
    int bufferSize;
    unsigned char buffer[BUFFER_LENGTH];
} stream_ctx;

int stream_init(stream_ctx* ctx, int padSize);
int stream_read(stream_ctx* ctx, FILE* fin);
int stream_read_next(stream_ctx* ctx, FILE* fin, unsigned char output[]);

#endif /* STREAM_H */
