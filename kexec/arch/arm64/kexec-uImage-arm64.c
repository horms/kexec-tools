/*
 * uImage support added by David Woodhouse <dwmw2@infradead.org>
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <image.h>
#include <kexec-uImage.h>
#include "../../kexec.h"
#include "kexec-arm64.h"

int uImage_arm64_probe(const char *kern_fname, off_t len, struct kexec_info *info)
{
	int ret;
	char *kernel_buf;

	kernel_buf = slurp_file(kern_fname, &len);
	ret = uImage_probe_kernel(kernel_buf, len, IH_ARCH_ARM64);

	/*  0 - valid uImage.
	 * -1 - uImage is corrupted.
	 *  1 - image is not a uImage.
	 */
	if (!ret) {
		info->kernel_fd = open(kern_fname, O_RDONLY);
		info->kernel_buf = kernel_buf;
		return 0;
	}
	else {
		free(kernel_buf);
		return -1;
	}
}

int uImage_arm64_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info)
{
	struct Image_info img;
	int ret;

	if (info->file_mode) {
		fprintf(stderr,
			"uImage is not supported in kexec_file\n");

		return EFAILED;
	}

	ret = uImage_load(buf, len, &img);
	if (ret)
		return ret;

	return image_arm64_load(argc, argv, img.buf, img.len, info);
}

void uImage_arm64_usage(void)
{
	printf(
"     An ARM64 U-boot uImage file, compressed or not, big or little endian.\n\n");
}
