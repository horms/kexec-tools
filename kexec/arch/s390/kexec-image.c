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
#include "kexec-s390.h"
#include <arch/options.h>

int
image_s390_load(int argc, char **argv, const char *kernel_buf,
		off_t kernel_size, struct kexec_info *info)
{
	void *krnl_buffer;
	char *rd_buffer;
	const char *command_line;
	const char *ramdisk;
	int command_line_len;
	off_t ramdisk_len;
	unsigned int ramdisk_origin;
	int opt;

	static const struct option options[] =
		{
			KEXEC_OPTIONS
			{"command-line",     1, 0, OPT_APPEND},
			{"initrd",           1, 0, OPT_RAMDISK},
			{0,                  0, 0, 0},
		};
	static const char short_options[] = KEXEC_OPT_STR "";

	ramdisk = NULL;
	command_line = NULL;
	ramdisk_len = 0;
	ramdisk_origin = 0;

	while ((opt = getopt_long(argc,argv,short_options,options,0)) != -1) {
		switch(opt) {
		case '?':
			usage();
			return -1;
			break;
		case OPT_APPEND:
			command_line = optarg;
			break;
		case OPT_RAMDISK:
			ramdisk = optarg;
			break;
		}
	}

	/* Process a given command_line: */
	if (command_line) {
		command_line_len = strlen(command_line) + 1; /* Remember the '\0' */
		if (command_line_len > COMMAND_LINESIZE) {
		        fprintf(stderr, "Command line too long.\n");
			return -1;
		}
	}

	/* Add kernel segment */
	add_segment(info, kernel_buf + IMAGE_READ_OFFSET,
		    kernel_size - IMAGE_READ_OFFSET, IMAGE_READ_OFFSET,
		    kernel_size - IMAGE_READ_OFFSET);

	/* We do want to change the kernel image */
	krnl_buffer = (void *) kernel_buf + IMAGE_READ_OFFSET;

	/* Load ramdisk if present */
	if (ramdisk) {
		rd_buffer = slurp_file(ramdisk, &ramdisk_len);
		if (rd_buffer == NULL) {
			fprintf(stderr, "Could not read ramdisk.\n");
			return -1;
		}
		ramdisk_origin = RAMDISK_ORIGIN_ADDR;
		add_segment(info, rd_buffer, ramdisk_len, RAMDISK_ORIGIN_ADDR, ramdisk_len);
	}
	
	/* Register the ramdisk in the kernel. */
	{
		unsigned long long *tmp;

		tmp = krnl_buffer + INITRD_START_OFFS;
		*tmp = (unsigned long long) ramdisk_origin;

		tmp = krnl_buffer + INITRD_SIZE_OFFS;
		*tmp = (unsigned long long) ramdisk_len;
	}

	/*
	 * We will write a probably given command line.
	 * First, erase the old area, then setup the new parameters:
	 */
	if (command_line) {
		memset(krnl_buffer + COMMAND_LINE_OFFS, 0, COMMAND_LINESIZE);
		memcpy(krnl_buffer + COMMAND_LINE_OFFS, command_line, strlen(command_line));
	}

	info->entry = (void *) IMAGE_READ_OFFSET;

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
	printf("--command-line=STRING Pass a custom command line STRING to the kernel.\n"
	       "--initrd=FILENAME     Use the file FILENAME as a ramdisk.\n"
		);
}
