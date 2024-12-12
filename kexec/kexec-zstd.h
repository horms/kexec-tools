#ifndef __KEXEC_ZSTD_H
#define __KEXEC_ZSTD_H

#include <sys/types.h>

char *zstd_decompress_file(const char *filename, off_t *r_size);
#endif /* __KEXEC_ZSTD_H */
