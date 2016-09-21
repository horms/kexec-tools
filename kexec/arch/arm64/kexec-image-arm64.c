/*
 * ARM64 kexec binary image support.
 */

#define _GNU_SOURCE
#include "kexec-arm64.h"

int image_arm64_probe(const char *kernel_buf, off_t kernel_size)
{
	const struct arm64_image_header *h;

	if (kernel_size < sizeof(struct arm64_image_header)) {
		dbgprintf("%s: No arm64 image header.\n", __func__);
		return -1;
	}

	h = (const struct arm64_image_header *)(kernel_buf);

	if (!arm64_header_check_magic(h)) {
		dbgprintf("%s: Bad arm64 image header.\n", __func__);
		return -1;
	}

	fprintf(stderr, "kexec: ARM64 binary image files are currently NOT SUPPORTED.\n");
	return -1;
}

int image_arm64_load(int argc, char **argv, const char *kernel_buf,
	off_t kernel_size, struct kexec_info *info)
{
	return -1;
}

void image_arm64_usage(void)
{
	printf(
"     An ARM64 binary image, compressed or not, big or little endian.\n"
"     Typically an Image, Image.gz or Image.lzma file.\n\n");
	printf(
"     ARM64 binary image files are currently NOT SUPPORTED.\n\n");
}
