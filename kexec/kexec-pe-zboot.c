/*
 * Generic PE compressed Image (vmlinuz, ZBOOT) support.
 *
 * Several distros use 'make zinstall' with CONFIG_ZBOOT
 * enabled to create UEFI PE images that contain
 * a decompressor and a compressed kernel image.
 *
 * Currently we cannot use kexec_file_load() to load vmlinuz
 * PE images that self decompress.
 *
 * To support ZBOOT, we should:
 * a). Copy the compressed contents of vmlinuz to a temporary file.
 * b). Decompress (gunzip-decompress) the contents inside the
 *     temporary file.
 * c). Validate the resulting image and write it back to the
 *     temporary file.
 * d). Pass the 'fd' of the temporary file to the kernel space.
 *
 * This module contains the arch independent code for the above,
 * arch specific PE and image checks should wrap calls
 * to functions in this module.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include "kexec.h"
#include <pe.h>
#include <kexec-pe-zboot.h>

#define FILENAME_IMAGE		"/tmp/ImageXXXXXX"

/*
 * Returns -1 : in case of error/invalid format (not a valid PE+compressed ZBOOT format.
 *
 * crude_buf: the content, which is read from the kernel file without any processing
 */
int pez_prepare(const char *crude_buf, off_t buf_sz, int *kernel_fd,
		off_t *kernel_size)
{
	int ret = -1;
	int fd = 0;
	char *fname = NULL;
	char *kernel_uncompressed_buf = NULL;
	char *parse;
	off_t original_file_sz, decompressed_size = 0;
	const struct linux_pe_zboot_header *z;
	struct pe32plus_opt_hdr *opt_hdr;
	struct data_directory *dir;

	z = (const struct linux_pe_zboot_header *)(crude_buf);

	if (memcmp(&z->image_type, "zimg", sizeof(z->image_type))) {
		dbgprintf("%s: PE doesn't contain a compressed kernel.\n", __func__);
		return -1;
	}

	/*
	 * At the moment its possible to create images with more compression
	 * algorithms than are supported here, error out if we detect that.
	 */
	if (memcmp(&z->compress_type, "gzip", 4) &&
	    memcmp(&z->compress_type, "zstd", 4) &&
	    memcmp(&z->compress_type, "lzma", 4)) {
		dbgprintf("%s: kexec can only decompress gziped, lzma and zstd images\n", __func__);
		return -1;
	}

	if (buf_sz < z->payload_offset + z->payload_size) {
		dbgprintf("%s: PE too small to contain complete payload.\n", __func__);
		return -1;
	}

	if (!(fname = strdup(FILENAME_IMAGE))) {
		dbgprintf("%s: Can't duplicate strings\n", __func__);
		return -1;
	}

	if ((fd = mkstemp(fname)) < 0) {
		dbgprintf("%s: Can't open file %s\n", __func__,	fname);
		ret = -1;
		goto fail_mkstemp;
	}

	if (write(fd, &crude_buf[z->payload_offset],
		  z->payload_size) != z->payload_size) {
		dbgprintf("%s: Can't write the compressed file %s\n",
				__func__, fname);
		ret = -1;
		goto fail_write;
	}

	kernel_uncompressed_buf = slurp_decompress_file(fname,
							&decompressed_size);

	original_file_sz = decompressed_size;
	dbgprintf("%s: decompressed size %ld\n", __func__, decompressed_size);

	/* Makefile.zboot pads Image with zero, but the trailing zero is not part of PE file */
	ret = get_pehdr_offset(kernel_uncompressed_buf);
	if (ret < 0)
		goto fail_bad_header;
	parse = kernel_uncompressed_buf + ret;
	parse += sizeof(struct pe_hdr);
	opt_hdr = (struct pe32plus_opt_hdr*)parse;
	parse += sizeof(struct pe32plus_opt_hdr);
	dir = (struct data_directory *)parse;
	if (opt_hdr->data_dirs > ((char *)&dir->certs - (char *)dir)/sizeof(struct data_dirent)) {
		/* If signed, the Attribute Certificate Table is always at the end of the PE file */
		if (dir->certs.virtual_address != 0 && dir->certs.size != 0) {
			original_file_sz = dir->certs.virtual_address + dir->certs.size;
			if (ftruncate(fd, 0)) {
				dbgprintf("%s: Can't truncate file %s\n", __func__, fname);
				goto fail_bad_header;
			}
		}
	}

	lseek(fd, 0, SEEK_SET);

	if (write(fd,  kernel_uncompressed_buf,
		  original_file_sz) != original_file_sz) {
		dbgprintf("%s: Can't write the decompressed file %s\n",
				__func__, fname);
		ret = -1;
		goto fail_bad_header;
	}

	*kernel_fd = open(fname, O_RDONLY);
	if (*kernel_fd == -1) {
		dbgprintf("%s: Failed to open file %s\n",
				__func__, fname);
		ret = -1;
		goto fail_bad_header;
	}

	*kernel_size = original_file_sz;
	dbgprintf("%s: done\n", __func__);

	ret = 0;
	goto fail_write;

fail_bad_header:
	free(kernel_uncompressed_buf);

fail_write:
	if (fd >= 0)
		close(fd);

	unlink(fname);

fail_mkstemp:
	free(fname);

	return ret;
}
