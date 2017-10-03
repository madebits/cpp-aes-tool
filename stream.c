#include <stdio.h>
#include <string.h>
#include "stream.h"

static size_t buffer_count = 0;

static void dumpctx(stream_ctx* ctx)
{
    if(!ctx->verbose) return;
    fprintf(stderr, "STREAM: last %d, rp %d, pad#: %d, buffer#: %d, enc: %d\n", ctx->last, ctx->rp, ctx->padSize, ctx->bufferSize, ctx->encodeMode);
    dump("STREAM.BUFFER", ctx->buffer, ctx->bufferSize * BLOCK_LENGTH, ctx->verbose);
}

void dump(char* msg, unsigned char b[], int b_len, int verbose)
{
    if(!verbose) return;
    int i = 0;
    fprintf(stderr, "%s (%d): ", msg, b_len);
    for (i = 0; i < b_len; i++)
    {
        fprintf(stderr, "%02x", b[i]);
    }
    fprintf(stderr, "\n");
}

/**
 * ms-help://MS.VSCC/MS.MSDNVS/security/aboutcrypto_8jjb.htm
 * (PKCS), PKCS #5, section 6.2
 */
static void pad_block(unsigned char b[], int b_len, int block_len)
{
    int pad = block_len - b_len;
    if(pad <= 0) return;
    memset(&b[b_len], pad, pad);
}

static int add(stream_ctx* ctx, int rp, int delta)
{
    return (ctx->bufferSize + (rp + delta)) % ctx->bufferSize;
}

int stream_init(stream_ctx* ctx, int encodeMode, int padSize, int verbose)
{
    if(ctx == 0) return -1;
    if(padSize < 0) padSize = 0;
    if(encodeMode) padSize = 0;
    ctx->rp = -1;
    ctx->last = -1;
    ctx->isLast = 0;
    ctx->padSize = padSize;
    ctx->bufferSize = padSize + 2;
    ctx->encodeMode = encodeMode;
    ctx->verbose = verbose;
    memset(ctx->buffer, 0, BSIZE(STREAM_BUFFER_LENGTH));
    return 0;
}

static size_t raw_read(stream_ctx* ctx, FILE* fin, unsigned char buffer[])
{
    size_t read_count;
    read_count = fread(buffer, (size_t)1, BSIZE_BLOCK_LENGTH, fin);
    if(ctx->verbose > 2) {
        buffer_count++;
        fprintf(stderr, "block (%ld): enc %d, read %ld, feof %d, ferror %d\n", buffer_count, ctx->encodeMode, read_count, feof(fin), ferror(fin));
    }
    return read_count;
}

int stream_read(stream_ctx* ctx, FILE* fin)
{
    int i;
    size_t read_count;
    unsigned char output[BLOCK_LENGTH];
    unsigned char* buffer = ctx->buffer;
    if((ctx == 0) || (fin == 0)) return -1;
    if(ctx->rp < 0)
    {
        for(i = 0; i < ctx->bufferSize; i++)
        {
            read_count = raw_read(ctx, fin, &buffer[i * BLOCK_LENGTH]);
            if(read_count != BSIZE_BLOCK_LENGTH)
            {
                if(read_count > 0)
                {
                    if(ctx->encodeMode)
                    {
                        pad_block(&buffer[i * BLOCK_LENGTH], (int)(read_count / sizeof(unsigned char)), BLOCK_LENGTH);
                        continue;
                    }
                    else
                    {
                        dumpctx(ctx);
                        return -1;
                    }
                }
                if(i == (ctx->bufferSize -1))
                {
                    ctx->last = 0;
                }
                else
                {
                    dumpctx(ctx);
                    return -1;
                }
            }
        }
        ctx->rp = 0;
    }
    else
    {
        if(ctx->last >= 0)
        {
            dumpctx(ctx);
            return -1;
        }

        read_count = raw_read(ctx, fin, output);
        if(read_count != BSIZE_BLOCK_LENGTH)
        {
            if(read_count > 0)
            {
                if(ctx->encodeMode)
                {
                    pad_block(output, (int)(read_count / sizeof(unsigned char)), BLOCK_LENGTH);
                }
                else
                {
                    dumpctx(ctx);
                    return -1;
                }
            }
        }

        if(read_count == 0)
        {
            ctx->last = add(ctx, ctx->rp, -(ctx->padSize + 1));
        }
        else
        {
            memcpy(&buffer[ctx->rp * BLOCK_LENGTH], output, BSIZE_BLOCK_LENGTH);
        }
        ctx->rp = add(ctx, ctx->rp, 1);
    }
    ctx->isLast = (ctx->rp == ctx->last);
    return 0;
}

int stream_read_next(stream_ctx* ctx, FILE* fin, unsigned char output[])
{
    int r = stream_read(ctx, fin);
    if(r < 0) return r;
    memcpy(output, &(ctx->buffer[ctx->rp * BLOCK_LENGTH]), BSIZE_BLOCK_LENGTH);
    return ctx->isLast ? 1 : 0;
}

int stream_read_pad(stream_ctx* ctx, unsigned char output[])
{
    int i;
    int rp;
    dumpctx(ctx);
    if((ctx == 0) || (ctx->last < 0)) return -1;
    for(i = 1; i <= ctx->padSize; i++)
    {
        rp = add(ctx, ctx->rp, i);
        memcpy(&output[(i - 1) * BLOCK_LENGTH], &(ctx->buffer[rp * BLOCK_LENGTH]), BSIZE_BLOCK_LENGTH);
    }
    return 0;
}
