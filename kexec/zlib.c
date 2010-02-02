#include "kexec-zlib.h"
#include "kexec.h"

#ifdef HAVE_LIBZ
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <zlib.h>

char *zlib_decompress_file(const char *filename, off_t *r_size)
{
	gzFile fp;
	int errnum;
	const char *msg;
	char *buf;
	off_t size, allocated;
	ssize_t result;

	if (!filename) {
		*r_size = 0;
		return 0;
	}
	fp = gzopen(filename, "rb");
	if (fp == 0) {
		msg = gzerror(fp, &errnum);
		if (errnum == Z_ERRNO) {
			msg = strerror(errno);
		}
		fprintf(stderr, "Cannot open `%s': %s\n", filename, msg);
		return NULL;
	}
	size = 0;
	allocated = 65536;
	buf = xmalloc(allocated);
	do {
		if (size == allocated) {
			allocated <<= 1;
			buf = xrealloc(buf, allocated);
		}
		result = gzread(fp, buf + size, allocated - size);
		if (result < 0) {
			if ((errno == EINTR) || (errno == EAGAIN))
				continue;

			msg = gzerror(fp, &errnum);
			if (errnum == Z_ERRNO) {
				msg = strerror(errno);
			}
			die ("read on %s of %ld bytes failed: %s\n",
				filename, (allocated - size) + 0UL, msg);
		}
		size += result;
	} while(result > 0);
	result = gzclose(fp);
	if (result != Z_OK) {
		msg = gzerror(fp, &errnum);
		if (errnum == Z_ERRNO) {
			msg = strerror(errno);
		}
		die ("Close of %s failed: %s\n", filename, msg);
	}
	*r_size =  size;
	return buf;
}
#else
char *zlib_decompress_file(const char *UNUSED(filename), off_t *UNUSED(r_size))
{
	return NULL;
}
#endif /* HAVE_ZLIB */
