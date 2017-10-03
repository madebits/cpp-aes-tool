#include <stdio.h>
#include <string.h>
#include "stream.h"

static int add(stream_ctx* ctx, int rp, int delta)
{
    return (ctx->bufferSize + (rp + delta)) % ctx->bufferSize;
}

int stream_init(stream_ctx* ctx, int padSize)
{
    if(ctx == 0) return -1;
    if(padSize < 0) padSize = 0;
    ctx->rp = -1;
    ctx->last = -1;
    ctx->isLast = 0;
    ctx->padSize = padSize;
    ctx->bufferSize = padSize + 2;
    memset(ctx->buffer, 0, BUFFER_LENGTH * sizeof(unsigned char));
    return 0;
}

int stream_read(stream_ctx* ctx, FILE* fin)
{
    int i;
    unsigned char output[BLOCK_LENGTH];
    unsigned char* buffer = ctx->buffer;
    if((ctx == 0) || (fin == 0)) return -1;
    if(ctx->rp < 0)
    {
        for(i = 0; i < ctx->bufferSize; i++)
        {
            if(fread(&buffer[i * BLOCK_LENGTH], 1, BLOCK_LENGTH, fin) != BLOCK_LENGTH)
            {
                if(i == (ctx->bufferSize -1))
                {
                    ctx->last = 0;
                } 
                else
                {
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
            return -1;
        }
        if(fread(output, 1, BLOCK_LENGTH, fin) != BLOCK_LENGTH)
        {
            ctx->last = add(ctx, ctx->rp, -(ctx->padSize + 1));
        }
        else
        {
            memcpy(&buffer[ctx->rp * BLOCK_LENGTH], output, BLOCK_LENGTH * sizeof(unsigned char));
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
    memcpy(output, &(ctx->buffer[ctx->rp * BLOCK_LENGTH]), BLOCK_LENGTH * sizeof(unsigned char));
    return ctx->isLast ? 1 : 0;
}
