/*
 * kexec/arch/s390/kexec-image.c
 *
 * (C) Copyright IBM Corp. 2005
 *
 * Author(s): Rolf Adelsberger <adelsberger@de.ibm.com>
 *            Heiko Carstens <heiko.carstens@de.ibm.com>
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include "../../kexec.h"
#include "../../kexec-syscall.h"
#include "../../kexec/crashdump.h"
#include "kexec-s390.h"
#include <arch/options.h>
#include <fcntl.h>

static uint64_t crash_base, crash_end;
static char command_line[COMMAND_LINESIZE];

static void add_segment_check(struct kexec_info *info, const void *buf,
			      size_t bufsz, unsigned long base, size_t memsz)
{
	if (info->kexec_flags & KEXEC_ON_CRASH)
		if (base + memsz > crash_end - crash_base)
			die("Not enough crashkernel memory to load segments\n");
	add_segment(info, buf, bufsz, crash_base + base, memsz);
}

int command_line_add(const char *str)
{
	if (strlen(command_line) + strlen(str) + 1 > COMMAND_LINESIZE) {
		fprintf(stderr, "Command line too long.\n");
		return -1;
	}
	strcat(command_line, str);
	return 0;
}

int image_s390_load_file(int argc, char **argv, struct kexec_info *info)
{
	const char *ramdisk = NULL;
	int opt;

	static const struct option options[] =
		{
			KEXEC_OPTIONS
			{"command-line",     1, 0, OPT_APPEND},
			{"append",           1, 0, OPT_APPEND},
			{"initrd",           1, 0, OPT_RAMDISK},
			{0,                  0, 0, 0},
		};
	static const char short_options[] = KEXEC_OPT_STR "";

	while ((opt = getopt_long(argc, argv, short_options, options, 0)) != -1) {
		switch(opt) {
		case OPT_APPEND:
			if (command_line_add(optarg))
				return -1;
			break;
		case OPT_RAMDISK:
			ramdisk = optarg;
			break;
		}
	}

	if (ramdisk) {
		info->initrd_fd = open(ramdisk, O_RDONLY);
		if (info->initrd_fd == -1) {
			fprintf(stderr, "Could not open initrd file %s:%s\n",
					ramdisk, strerror(errno));
			return -1;
		}
	}

	info->command_line = command_line;
	info->command_line_len = strlen (command_line) + 1;

	return 0;
}

int
image_s390_load(int argc, char **argv, const char *kernel_buf,
		off_t kernel_size, struct kexec_info *info)
{
	void *krnl_buffer;
	char *rd_buffer;
	const char *ramdisk;
	off_t ramdisk_len;
	unsigned int ramdisk_origin;
	int opt;

	if (info->file_mode)
		return image_s390_load_file(argc, argv, info);

	static const struct option options[] =
		{
			KEXEC_OPTIONS
			{"command-line",     1, 0, OPT_APPEND},
			{"append",           1, 0, OPT_APPEND},
			{"initrd",           1, 0, OPT_RAMDISK},
			{0,                  0, 0, 0},
		};
	static const char short_options[] = KEXEC_OPT_STR "";

	command_line[0] = 0;
	ramdisk = NULL;
	ramdisk_len = 0;
	ramdisk_origin = 0;

	while ((opt = getopt_long(argc,argv,short_options,options,0)) != -1) {
		switch(opt) {
		case OPT_APPEND:
			if (command_line_add(optarg))
				return -1;
			break;
		case OPT_RAMDISK:
			ramdisk = optarg;
			break;
		}
	}

	if (info->kexec_flags & KEXEC_ON_CRASH) {
		if (parse_iomem_single("Crash kernel\n", &crash_base,
				       &crash_end))
			return -1;
	}

	/* Add kernel segment */
	add_segment_check(info, kernel_buf + IMAGE_READ_OFFSET,
		    kernel_size - IMAGE_READ_OFFSET, IMAGE_READ_OFFSET,
		    kernel_size - IMAGE_READ_OFFSET);

	/* We do want to change the kernel image */
	krnl_buffer = (void *) kernel_buf + IMAGE_READ_OFFSET;

	/*
	 * Load ramdisk if present: If image is larger than RAMDISK_ORIGIN_ADDR,
	 * we load the ramdisk directly behind the image with 1 MiB alignment.
	 */
	if (ramdisk) {
		rd_buffer = slurp_file_mmap(ramdisk, &ramdisk_len);
		if (rd_buffer == NULL) {
			fprintf(stderr, "Could not read ramdisk.\n");
			return -1;
		}
		ramdisk_origin = MAX(RAMDISK_ORIGIN_ADDR, kernel_size);
		ramdisk_origin = _ALIGN_UP(ramdisk_origin, 0x100000);
		add_segment_check(info, rd_buffer, ramdisk_len,
				  ramdisk_origin, ramdisk_len);
	}
	if (info->kexec_flags & KEXEC_ON_CRASH) {
		if (load_crashdump_segments(info, crash_base, crash_end))
			return -1;
	} else {
		info->entry = (void *) IMAGE_READ_OFFSET;
	}

	/* Register the ramdisk and crashkernel memory in the kernel. */
	{
		unsigned long long *tmp;

		tmp = krnl_buffer + INITRD_START_OFFS;
		*tmp = (unsigned long long) ramdisk_origin;

		tmp = krnl_buffer + INITRD_SIZE_OFFS;
		*tmp = (unsigned long long) ramdisk_len;

		if (info->kexec_flags & KEXEC_ON_CRASH) {
			tmp = krnl_buffer + OLDMEM_BASE_OFFS;
			*tmp = crash_base;

			tmp = krnl_buffer + OLDMEM_SIZE_OFFS;
			*tmp = crash_end - crash_base + 1;
		}
	}
	/*
	 * We will write a probably given command line.
	 * First, erase the old area, then setup the new parameters:
	 */
	if (strlen(command_line) != 0) {
		memset(krnl_buffer + COMMAND_LINE_OFFS, 0, COMMAND_LINESIZE);
		memcpy(krnl_buffer + COMMAND_LINE_OFFS, command_line, strlen(command_line));
	}
	return 0;
}

int 
image_s390_probe(const char *UNUSED(kernel_buf), off_t UNUSED(kernel_size))
{
	/*
	 * Can't reliably tell if an image is valid,
	 * therefore everything is valid.
	 */
	return 0;
}

void
image_s390_usage(void)
{
	printf("--command-line=STRING Set the kernel command line to STRING.\n"
	       "--append=STRING       Set the kernel command line to STRING.\n"
	       "--initrd=FILENAME     Use the file FILENAME as a ramdisk.\n"
		);
}
