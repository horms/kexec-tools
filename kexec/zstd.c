#include "kexec-zstd.h"
#include "kexec.h"

#include "config.h"

#ifdef HAVE_LIBZSTD
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <zstd.h>


/*
 * Reimplementation of private function available if zstd is
 * statically linked. Remove when it becomes public.
 */
unsigned ZSTD_isFrame(const void* buffer, size_t size)
{
	uint8_t *buf = (uint8_t *)buffer;
	/* Magic zstd frame header value */
	if ((buf[0] == 0x28) &&
	    (buf[1] == 0xB5) &&
	    (buf[2] == 0x2F) &&
	    (buf[3] == 0xFD))
		return 1;

	return 0;
}

/*
 * A guess at the max compression ratio for buffer overallocation.
 * Real values are frequently around 4:1, if this is wrong
 * it simply results in buffer reallocation and the decompression
 * operation being restarted from where it stopped.
 */
#define EXPECTED_RATIO 8

/*
 * This supports the streaming compression mode the kernel uses
 * that can result in multiple zstd frames comprising a single
 * compressed image. In order too be a bit more efficient than
 * the libz/lzma implementations, we attempt to discover the input
 * and output image sizes before performing the decompression.
 * But, in streaming mode the first frame may not have a length
 * or it seems the length could be incorrect if multiple frames
 * are appended together. So, its written with buffer resize logic
 * but a guess at the compression ratio is made to avoid the resize/copy
 * operation. Ideally this code efficiently allocates the
 * correct input buffer, and no more than 2-3x the output buffer
 * size so that it can perform the decompress operation with a
 * single decompress call.
 */
char *zstd_decompress_file(const char *filename, off_t *r_size)
{
	void *cBuff = NULL;
	ZSTD_DCtx* dctx = NULL;
	FILE *fp = NULL; /* use c streams to match gzip/lzma logic */
	struct stat fp_stats;
	uint8_t magic[4];
	size_t ret;

	ZSTD_outBuffer output = { NULL, 0, 0 };
	ZSTD_inBuffer input = { NULL, 0, 0 };

	dbgprintf("Try zstd decompression.\n");

	*r_size = 0;
	if (!filename) {
		return NULL;
	}
	if (stat(filename, &fp_stats)) {
		dbgprintf("Cannot stat `%s'\n", filename);
		return NULL;
	}
	if (fp_stats.st_size < sizeof(magic)) {
		dbgprintf("short file\n");
		return NULL;
	}
	input.size = fp_stats.st_size;

	fp = fopen(filename, "rb");
	if (fp == 0) {
		dbgprintf("Cannot open `%s'\n", filename);
		goto fail;
	}
	/* before we read the whole buffer see if this looks like a zstd frame */
	if (fread(&magic, 1, sizeof(magic), fp) != sizeof(magic)) {
		dbgprintf("Unable to read zstd header\n");
		goto fail;
	}

	if (!ZSTD_isFrame((void*)&magic, sizeof(magic))) {
		dbgprintf("Not zstd compressed\n");
		goto fail;
	}

	cBuff = xmalloc(input.size);
	input.src = cBuff; /* use cBuff ptr to avoid const/mismatches */
	rewind(fp);
	if (fread(cBuff, 1, input.size, fp) != input.size) {
		dbgprintf("Unable to read compressed data\n");
		goto fail;
	}
	fclose(fp);
	fp = NULL;


	output.size = ZSTD_getFrameContentSize(input.src, input.size);
	if (output.size == ZSTD_CONTENTSIZE_ERROR) {
		dbgprintf("not compressed by zstd\n");
		goto fail;
	}

	if (output.size == ZSTD_CONTENTSIZE_UNKNOWN) {
		dbgprintf("original zstd size unknown!\n");
		/*
		 * The compressed size is an optional field in the header
		 * So we guess at the compression ratio to avoid reallocating
		 * the buffer, but this can fail so we still have code to
		 * handle that case.
		 */
		output.size = fp_stats.st_size * EXPECTED_RATIO;
	}

	output.dst = xmalloc(output.size);

	dctx = ZSTD_createDCtx();
	if (dctx == NULL) {
		dbgprintf("zstd context allocation error\n");
		goto fail;
	}

	do {
		if (output.pos == output.size) {
			output.size <<= 1;
			output.dst = xrealloc(output.dst, output.size);
		}

		ret = ZSTD_decompressStream(dctx, &output , &input);
		if (ZSTD_isError(ret)) {
			dbgprintf("zstd error %s\n", ZSTD_getErrorName(ret));
			goto fail;
		}
		dbgprintf("zstd decompressed input=%ld to output=%ld\n", input.pos, output.pos);

	} while ((input.pos < input.size) || ret);

	free(cBuff);
	ZSTD_freeDCtx(dctx);

	*r_size = output.pos;

	return output.dst;

fail:
	if (fp)
		fclose(fp);
	if (dctx)
		ZSTD_freeDCtx(dctx);
	if (output.dst)
		free(output.dst);
	if (cBuff)
		free(cBuff);

	return NULL;

}
#else

char *zstd_decompress_file(const char *filename, off_t *r_size)
{
	return NULL;
}
#endif
