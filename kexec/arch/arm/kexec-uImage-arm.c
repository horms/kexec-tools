/*
 * uImage support added by Marc Andre Tanner <mat@brain-dump.org>
 */
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <image.h>
#include "../../kexec.h"
#include "kexec-arm.h"

int uImage_arm_probe(const char *buf, off_t len)
{
	struct image_header header;

	if (len < sizeof(header))
		return -1;

	memcpy(&header, buf, sizeof(header));

	if (cpu_to_be32(header.ih_magic) != IH_MAGIC)
		return -1;

	/* XXX: check CRC Checksum? */

	return 0;
}

int uImage_arm_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info)
{
	return zImage_arm_load(argc, argv, buf + sizeof(struct image_header),
	                       len - sizeof(struct image_header), info);
}
