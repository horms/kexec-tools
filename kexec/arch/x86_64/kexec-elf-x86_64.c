/*
 * kexec: Linux boots Linux
 *
 * Copyright (C) 2003-2005  Eric Biederman (ebiederm@xmission.com)
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <elf.h>
#include <x86/x86-linux.h>
#include "../../kexec.h"
#include "../../kexec-elf.h"
#include "../../kexec-elf-boot.h"
#include "../i386/x86-linux-setup.h"
#include "kexec-x86_64.h"
#include <arch/options.h>

static const int probe_debug = 0;

int elf_x86_64_probe(const char *buf, off_t len)
{
	
	struct mem_ehdr ehdr;
	int result;
	result = build_elf_exec_info(buf, len, &ehdr);
	if (result < 0) {
		if (probe_debug) {
			fprintf(stderr, "Not an ELF executable\n");
		}
		goto out;
	}

	/* Verify the architecuture specific bits */
	if (ehdr.e_machine != EM_X86_64) {
		/* for a different architecture */
		if (probe_debug) {
			fprintf(stderr, "Not x86_64 ELF executable\n");
		}
		result = -1;
		goto out;
	}
	result = 0;
 out:
	free_elf_info(&ehdr);
	return result;
}

void elf_x86_64_usage(void)
{
	printf(	"    --command-line=STRING Set the kernel command line to STRING\n"
		"    --append=STRING       Set the kernel command line to STRING\n"
		"    --initrd=FILE         Use FILE as the kernel's initial ramdisk.\n"
		"    --ramdisk=FILE        Use FILE as the kernel's initial ramdisk.\n"
		"    --args-linux          Pass linux kernel style options\n"
		"    --args-elf            Pass elf boot notes\n"
		"    --args-none           Jump directly from the kernel\n"
		);
}

int elf_x86_64_load(int argc, char **argv, const char *buf, off_t len, 
	struct kexec_info *info)
{
	struct mem_ehdr ehdr;
	const char *command_line;
	int command_line_len;
	const char *ramdisk;
	unsigned long entry, max_addr;
	int arg_style;
#define ARG_STYLE_ELF   0
#define ARG_STYLE_LINUX 1
#define ARG_STYLE_NONE  2
	int opt;
#define OPT_APPEND	(OPT_ARCH_MAX+0)
#define OPT_RAMDISK	(OPT_ARCH_MAX+1)
#define OPT_ARGS_ELF    (OPT_ARCH_MAX+2)
#define OPT_ARGS_LINUX  (OPT_ARCH_MAX+3)
#define OPT_ARGS_NONE   (OPT_ARCH_MAX+4)

	static const struct option options[] = {
		KEXEC_ARCH_OPTIONS
		{ "command-line",	1, NULL, OPT_APPEND },
		{ "append",		1, NULL, OPT_APPEND },
		{ "initrd",		1, NULL, OPT_RAMDISK },
		{ "ramdisk",		1, NULL, OPT_RAMDISK },
		{ "args-elf",		0, NULL, OPT_ARGS_ELF },
		{ "args-linux",		0, NULL, OPT_ARGS_LINUX },
		{ "args-none",		0, NULL, OPT_ARGS_NONE },
		{ 0, 			0, NULL, 0 },
	};

	static const char short_options[] = KEXEC_ARCH_OPT_STR "";

	/*
	 * Parse the command line arguments
	 */
	arg_style = ARG_STYLE_ELF;
	command_line = 0;
	ramdisk = 0;
	while((opt = getopt_long(argc, argv, short_options, options, 0)) != -1) {
		switch(opt) {
		default:
			/* Ignore core options */
			if (opt < OPT_ARCH_MAX) {
				break;
			}
			fprintf(stderr, "Unknown option: opt: %d\n", opt);
		case '?':
			usage();
			return -1;
		case OPT_APPEND:
			command_line = optarg;
			break;
		case OPT_RAMDISK:
			ramdisk = optarg;
			break;
		case OPT_ARGS_ELF: 
			arg_style = ARG_STYLE_ELF;
			break;
		case OPT_ARGS_LINUX:
			arg_style = ARG_STYLE_LINUX;
			break;
		case OPT_ARGS_NONE:
#ifdef __x86_64___
			arg_style = ARG_STYLE_NONE;
#else
			die("--args-none only works on arch x86_64\n");
#endif
			break;
		}
	}
	command_line_len = 0;
	if (command_line) {
		command_line_len = strlen(command_line) +1;
	}

	/* Load the ELF executable */
	elf_exec_build_load(info, &ehdr, buf, len);

	entry = ehdr.e_entry;
	max_addr = elf_max_addr(&ehdr);

	/* Do we want arguments? */
	if (arg_style != ARG_STYLE_NONE) {
		/* Load the setup code */
		elf_rel_build_load(info, &info->rhdr, purgatory, purgatory_size,
			0, ULONG_MAX, 1);
	}
	if (arg_style == ARG_STYLE_NONE) {
		info->entry = (void *)entry;

	}
	else if (arg_style == ARG_STYLE_ELF) {
		unsigned long note_base;
		struct entry64_regs regs;

		/* Setup the ELF boot notes */
		note_base = elf_boot_notes(info, max_addr,
			command_line, command_line_len);

		/* Initialize the registers */
		elf_rel_get_symbol(&info->rhdr, "entry64_regs", &regs, sizeof(regs));
		regs.rdi = note_base;   /* The notes (arg1) */
		regs.rip = entry;       /* The entry point */
		regs.rsp = elf_rel_get_addr(&info->rhdr, "stack_end"); /* Stack, unused */
		elf_rel_set_symbol(&info->rhdr, "entry64_regs", &regs, sizeof(regs));

		if (ramdisk) {
			die("Ramdisks not supported with generic elf arguments");
		}
	}
	else if (arg_style == ARG_STYLE_LINUX) {
		struct x86_linux_faked_param_header *hdr;
		unsigned long param_base;
		const unsigned char *ramdisk_buf;
		off_t ramdisk_length;
		struct entry64_regs regs;

		/* Get the linux parameter header */
		hdr = xmalloc(sizeof(*hdr));
		param_base = add_buffer(info, hdr, sizeof(*hdr), sizeof(*hdr),
			16, 0, max_addr, 1);

		/* Initialize the parameter header */
		memset(hdr, 0, sizeof(*hdr));
		init_linux_parameters(&hdr->hdr);

		/* Add a ramdisk to the current image */
		ramdisk_buf = 0;
		ramdisk_length = 0;
		if (ramdisk) {
			ramdisk_buf = slurp_file(ramdisk, &ramdisk_length);
		}

		/* Tell the kernel what is going on */
		setup_linux_bootloader_parameters(info, &hdr->hdr, param_base, 
			offsetof(struct x86_linux_faked_param_header, command_line),
			command_line, command_line_len,
			ramdisk_buf, ramdisk_length);

		/* Fill in the information bios calls would usually provide */
		setup_linux_system_parameters(&hdr->hdr, info->kexec_flags);

		/* Initialize the registers */
		elf_rel_get_symbol(&info->rhdr, "entry64_regs", &regs, sizeof(regs));
		regs.rbx = 0;		/* Bootstrap processor */
		regs.rsi = param_base;	/* Pointer to the parameters */
		regs.rip = entry;	/* the entry point */
		regs.rsp = elf_rel_get_addr(&info->rhdr, "stack_end"); /* Stack, unused */
		elf_rel_set_symbol(&info->rhdr, "entry64_regs", &regs, sizeof(regs));
	}
	else {
		die("Unknown argument style\n");
	}
	return 0;
}
