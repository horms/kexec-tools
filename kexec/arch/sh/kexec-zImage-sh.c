/*
 * kexec-zImage-sh.c - kexec zImage loader for the SH
 * Copyright (C) 2005 kogiidena@eggplant.ddo.jp
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <elf.h>
#include <boot/elf_boot.h>
#include <ip_checksum.h>
#include "../../kexec.h"
#include "../../kexec-elf.h"
#include <arch/options.h>
#include "kexec-sh.h"

static const int probe_debug = 0;

/*
 * zImage_sh_probe - sanity check the elf image
 *
 * Make sure that the file image has a reasonable chance of working.
 */
int zImage_sh_probe(const char *buf, off_t len)
{
	if (memcmp(&buf[0x202], "HdrS", 4) != 0) {
	        fprintf(stderr, "Not a zImage\n");
	        return -1;
	}
	return 0;
}

void zImage_sh_usage(void)
{
	printf(
		
    " --append=STRING      Set the kernel command line to STRING.\n"
    " --empty-zero=ADDRESS Set the kernel top ADDRESS. \n\n");

}

int zImage_sh_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info)
{
        char *command_line;
	int opt;
	unsigned long empty_zero, area;
	unsigned char *param;
	unsigned long *paraml;

	static const struct option options[] = {
       	        KEXEC_ARCH_OPTIONS
		{0, 0, 0, 0},
	};

	static const char short_options[] = KEXEC_ARCH_OPT_STR "";

	command_line = 0;
	empty_zero = get_empty_zero(NULL);
	while ((opt = getopt_long(argc, argv, short_options, options, 0)) != -1) {
		switch (opt) {
		default:
			/* Ignore core options */
			if (opt < OPT_ARCH_MAX) {
				break;
			}
		case '?':
			usage();
			return -1;
		case OPT_APPEND:
			command_line = optarg;
			break;
		case OPT_EMPTYZERO:
			empty_zero = get_empty_zero(optarg); 
			break;
		}
	}
	param = xmalloc(4096);
	memset(param, 0, 4096);
	area       = empty_zero & 0x1c000000;
	if (!command_line) {
	        command_line = get_append();
	}
	strncpy(&param[256], command_line, strlen(command_line));
        paraml = (unsigned long *)param;
	// paraml[0] = 1;  // readonly flag is set as default

	add_segment(info, param, 4096, empty_zero, 4096);
	add_segment(info, buf,   len,  (area | 0x00210000), len);

	/* For now we don't have arguments to pass :( */
	info->entry = (void *)(0x80210000 | area);
	return 0;
}
