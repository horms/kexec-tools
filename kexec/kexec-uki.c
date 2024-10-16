#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pe.h>
#include "kexec.h"

#define UKI_LINUX_SECTION ".linux"
#define UKI_INITRD_SECTION ".initrd"
#define UKI_CMDLINE_SECTION ".cmdline"
#define UKI_DTB_SECTION ".dtb"

#define FILENAME_UKI_INITRD          "/tmp/InitrdXXXXXX"

static int embeded_linux_format_index = -1;

/*
 * Return -1 if not PE, else offset of the PE header
 */
static int get_pehdr_offset(const char *buf)
{
	int pe_hdr_offset;

	pe_hdr_offset = *((int *)(buf + 0x3c));
	buf += pe_hdr_offset;
	if (!!memcmp(buf, "PE\0\0", 4)) {
		printf("Not a PE file\n");
		return -1;
	}

	return pe_hdr_offset;
}

int uki_image_probe(const char *file_buf, off_t buf_sz)
{
	struct pe_hdr *pe_hdr;
	struct pe32plus_opt_hdr *opt_hdr;
	struct section_header *sect_hdr;
	int pe_hdr_offset, section_nr, linux_sz = -1;
	char *pe_part_buf, *linux_src;
	char *initrd_fname = NULL;
	int initrd_fd = -1;

	pe_hdr_offset = get_pehdr_offset(file_buf);
	pe_part_buf = (char *)file_buf + pe_hdr_offset;
	pe_hdr = (struct pe_hdr *)pe_part_buf;
	if (pe_hdr->opt_hdr_size == 0) {
		printf("ERR: optional header is missing\n");
		return -1;
	}
	section_nr = pe_hdr->sections;
	opt_hdr = (struct pe32plus_opt_hdr *)(pe_part_buf + sizeof(struct pe_hdr));
	sect_hdr = (struct section_header *)((char *)opt_hdr + pe_hdr->opt_hdr_size);

	for (int i = 0; i < section_nr; i++) {
		if (!strcmp(sect_hdr->name, UKI_LINUX_SECTION)) {
			/* data_addr is relative to the whole file */
			linux_src = (char *)file_buf + sect_hdr->data_addr;
			linux_sz = sect_hdr->raw_data_size;

		} else if (!strcmp(sect_hdr->name, UKI_INITRD_SECTION)) {
			if (!(initrd_fname = strdup(FILENAME_UKI_INITRD))) {
				dbgprintf("%s: Can't duplicate strings\n", __func__);
				goto next;
			}

			if ((initrd_fd = mkstemp(initrd_fname)) < 0) {
				dbgprintf("%s: Can't open file %s\n", __func__,	initrd_fname);
				goto next;
			}

			if (write(initrd_fd, (char *)file_buf + sect_hdr->data_addr,
					sect_hdr->raw_data_size) != sect_hdr->raw_data_size) {
				dbgprintf("%s: Can't write the compressed file %s\n",
						__func__, initrd_fname);
				goto next;
			} else {
				implicit_initrd_fd = open(initrd_fname, O_RDONLY);
				close(initrd_fd);
			}
		}
next:
		sect_hdr++;
	}

	if (linux_sz == -1) {
		printf("ERR: can not find .linux section\n");
		return -1;
	}
	/*
	 * After stripping the UKI coat, the real kernel format can be handled now.
	 */
	for (int i = 0; i < file_types; i++) {
		/* kernel_fd will be created by probe */
		if (file_type[i].probe != uki_image_probe &&
		    file_type[i].probe(linux_src, linux_sz) >= 0) {
			embeded_linux_format_index = i;
			break;
		}
	}
	if (embeded_linux_format_index < 0) {
		printf("Can not recognize the kernel format in .linux section\n");
		return -1;
	}
	return 0;
}

int uki_image_load(int argc, char **argv, const char *buf, off_t len,
			struct kexec_info *info)
{
	return file_type[embeded_linux_format_index].load(argc, argv, buf, len, info);
}

void uki_image_usage(void)
{
	printf(
"     An UKI image.\n");
}
