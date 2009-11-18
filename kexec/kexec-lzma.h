#ifndef __KEXEC_LZMA_H
#define __KEXEC_LZMA_H

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include <lzma.h>

#include "config.h"

#ifdef HAVE_LIBLZMA
#define kBufferSize (1 << 15)

typedef struct lzfile {
	uint8_t buf[kBufferSize];
	lzma_stream strm;
	FILE *file;
	int encoding;
	int eof;
} LZFILE;

LZFILE *lzopen(const char *path, const char *mode);
int lzclose(LZFILE *lzfile);
ssize_t lzread(LZFILE *lzfile, void *buf, size_t len);
#endif /* HAVE_LIBLZMA */

char *lzma_decompress_file(const char *filename, off_t *r_size);
#endif /* __KEXEC_LZMA_H */
