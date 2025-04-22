/* SPDX-License-Identifier: GPL-2.0 */
/*
 * RISC-V kexec binary image support.
 *
 * Author: Song Shuai <songhshuaishuai@tinylab.org>
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include "image-header.h"
#include "kexec.h"
#include "kexec-riscv.h"
#include "kexec-syscall.h"
#include "arch/options.h"

int image_riscv_probe(const char *kernel_buf, off_t kernel_size)
{
	const struct riscv_image_header *h;

	if (kernel_size < sizeof(struct riscv_image_header)) {
		dbgprintf("%s: No riscv image header.\n", __func__);
		return -1;
	}

	h = (const struct riscv_image_header *)(kernel_buf);

	if (!riscv_header_check_magic(h)) {
		dbgprintf("%s: Bad riscv image header.\n", __func__);
		return -1;
	}

	return 0;
}

int image_riscv_load(int argc, char **argv, const char *kernel_buf,
	off_t kernel_size, struct kexec_info *info)
{
	const struct riscv_image_header *h;
	unsigned long text_offset, image_size;
	off_t new_base_addr = 0;

	int ret;

	if (info->file_mode) {
		return prepare_kexec_file_options(info);
	}

	h = (const struct riscv_image_header *)(kernel_buf);

	/* Check header */
	if (!h->image_size){
		dbgprintf("Kernel image size is NULL\n");
		ret = EFAILED;
		goto exit;
	}

	if(riscv_header_check_endiannes(h)){
		dbgprintf("Kernel image was built as big endian\n");
		ret = EFAILED;
		goto exit;
	}

	text_offset = riscv_header_text_offset(h);
	image_size = riscv_header_image_size(h);

	/* Setup the entry and segments */

	ret = riscv_find_pbase(info, &new_base_addr, image_size, text_offset);
	if (ret < 0) {
		fprintf(stderr, "Could not find a memory region for the "
				"provided Image\n");
		goto exit;
	}

	info->entry = (void *) new_base_addr;
	dbgprintf("Entry point for the Image: 0x%lX\n", new_base_addr);

	add_segment(info, kernel_buf, kernel_size, new_base_addr, image_size);

	ret = load_extra_segments(info, text_offset, image_size, ULONG_MAX);
exit:
        if (ret)
                fprintf(stderr, "kexec: load failed.\n");
        return ret;
}

void image_riscv_usage(void)
{
	printf(
"     An RISC-V binary image, uncompressed, little endian.\n"
"     Typically an Image file.\n\n");
}
