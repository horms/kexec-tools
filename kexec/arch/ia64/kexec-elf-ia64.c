/*
 * kexec: Linux boots Linux
 *
 * Copyright (C) 2003,2004  Eric Biederman (ebiederm@xmission.com)
 * Copyright (C) 2004 Albert Herranz
 * Copyright (C) 2004 Silicon Graphics, Inc.
 *   Jesse Barnes <jbarnes@sgi.com>
 * Copyright (C) 2004 Khalid Aziz <khalid.aziz@hp.com> Hewlett Packard Co
 * Copyright (C) 2005 Zou Nan hai <nanhai.zou@intel.com> Intel Corp
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation (version 2 of the License).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
#include <limits.h>
#include <elf.h>
#include <boot/elf_boot.h>
#include <ip_checksum.h>
#include "../../kexec.h"
#include "../../kexec-elf.h"
#include <arch/options.h>

static const int probe_debug = 0;

/*
 * elf_ia64_probe - sanity check the elf image
 *
 * Make sure that the file image has a reasonable chance of working.
 */
int elf_ia64_probe(const char *buf, off_t len)
{
	struct mem_ehdr ehdr;
	int result;
	result = build_elf_exec_info(buf, len, &ehdr);
	if (result < 0) {
		if (probe_debug) {
			fprintf(stderr, "Not an ELF executable\n");
		}
		return -1;
	}
	/* Verify the architecuture specific bits */
	if (ehdr.e_machine != EM_IA_64) {
		/* for a different architecture */
		if (probe_debug) {
			fprintf(stderr, "Not for this architecture.\n");
		}
		return -1;
	}
	return 0;
}

void elf_ia64_usage(void)
{
	printf(
		"    --command-line=STRING Set the kernel command line to STRING.\n"
		"    --append=STRING       Set the kernel command line to STRING.\n"
		"    --initrd=FILE       Use FILE as the kernel's initial ramdisk.\n");
}

int elf_ia64_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info)
{
	struct mem_ehdr ehdr;
	const char *command_line, *ramdisk=0;
	char *ramdisk_buf = NULL;
	off_t ramdisk_size = 0;
	unsigned long command_line_len;
	unsigned long entry, max_addr, gp_value;
	unsigned command_line_base, ramdisk_base;
	int result;
	int opt;
#define OPT_APPEND	(OPT_ARCH_MAX+0)
#define OPT_RAMDISK	(OPT_ARCH_MAX+1)
	static const struct option options[] = {
		KEXEC_ARCH_OPTIONS
		{"command-line", 1, 0, OPT_APPEND},
		{"append",       1, 0, OPT_APPEND},
		{"initrd",       1, 0, OPT_RAMDISK},
		{0, 0, 0, 0},
	};

	static const char short_options[] = KEXEC_ARCH_OPT_STR "";

	command_line = 0;
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
		case OPT_RAMDISK:
			ramdisk = optarg;
			break;
		}
	}
	command_line_len = 0;
	if (command_line) {
		command_line_len = strlen(command_line) + 16;
	}

	/* Parse the Elf file */
	result = build_elf_exec_info(buf, len, &ehdr);
	if (result < 0) {
		fprintf(stderr, "ELF parse failed\n");
		free_elf_info(&ehdr);
		return result;
	}
	entry = ehdr.e_entry;
	max_addr = elf_max_addr(&ehdr);

	/* Load the Elf data */
	result = elf_exec_load(&ehdr, info);
	if (result < 0) {
		fprintf(stderr, "ELF load failed\n");
		free_elf_info(&ehdr);
		return result;
	}


	/* Load the setup code */
	elf_rel_build_load(info, &info->rhdr, purgatory, purgatory_size,
			0x80000, ULONG_MAX, 1);

	if (command_line_len) {
		char *cmdline = xmalloc(command_line_len);
		strcpy(cmdline, command_line);
		command_line_len = (command_line_len + 15)&(~15);
		elf_rel_set_symbol(&info->rhdr, "__command_line_len",
				&command_line_len, sizeof(long));
		command_line_base = add_buffer(info, cmdline,
					command_line_len, command_line_len,
					16, 0, max_addr, 1);
		elf_rel_set_symbol(&info->rhdr, "__command_line",
				&command_line_base, sizeof(long));
	}
	
	if (ramdisk) {
		ramdisk_buf = slurp_file(ramdisk, &ramdisk_size);
		ramdisk_base = add_buffer(info, ramdisk_buf, ramdisk_size,
				ramdisk_size,
				getpagesize(), 0, max_addr, 1);
		elf_rel_set_symbol(&info->rhdr, "__ramdisk_base",
				&ramdisk_base, sizeof(long));
		elf_rel_set_symbol(&info->rhdr, "__ramdisk_size",
				&ramdisk_size, sizeof(long));
	}

	gp_value = info->rhdr.rel_addr + 0x200000;
        elf_rel_set_symbol(&info->rhdr, "__gp_value", &gp_value,
                        sizeof(gp_value));

	elf_rel_set_symbol(&info->rhdr, "__kernel_entry", &entry, sizeof(entry));
	free_elf_info(&ehdr);
	return 0;
}
