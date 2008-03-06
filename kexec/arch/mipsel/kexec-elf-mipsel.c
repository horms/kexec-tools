/*
 * kexec-elf-mipsel.c - kexec Elf loader for mips
 * Copyright (C) 2007 Francesco Chiechi, Alessandro Rubini
 * Copyright (C) 2007 Tvblob s.r.l.
 *
 * derived from ../ppc/kexec-elf-ppc.c
 * Copyright (C) 2004 Albert Herranz
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
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
#include "kexec-mipsel.h"
#include <arch/options.h>

static const int probe_debug = 0;

#define BOOTLOADER         "kexec"
#define MAX_COMMAND_LINE   256

#define UPSZ(X) ((sizeof(X) + 3) & ~3)
static struct boot_notes {
	Elf_Bhdr hdr;
	Elf_Nhdr bl_hdr;
	unsigned char bl_desc[UPSZ(BOOTLOADER)];
	Elf_Nhdr blv_hdr;
	unsigned char blv_desc[UPSZ(BOOTLOADER_VERSION)];
	Elf_Nhdr cmd_hdr;
	unsigned char command_line[0];
} elf_boot_notes = {
	.hdr = {
		.b_signature = 0x0E1FB007,
		.b_size = sizeof(elf_boot_notes),
		.b_checksum = 0,
		.b_records = 3,
	},
	.bl_hdr = {
		.n_namesz = 0,
		.n_descsz = sizeof(BOOTLOADER),
		.n_type = EBN_BOOTLOADER_NAME,
	},
	.bl_desc = BOOTLOADER,
	.blv_hdr = {
		.n_namesz = 0,
		.n_descsz = sizeof(BOOTLOADER_VERSION),
		.n_type = EBN_BOOTLOADER_VERSION,
	},
	.blv_desc = BOOTLOADER_VERSION,
	.cmd_hdr = {
		.n_namesz = 0,
		.n_descsz = 0,
		.n_type = EBN_COMMAND_LINE,
	},
};


int elf_mipsel_probe(const char *buf, off_t len)
{

	struct mem_ehdr ehdr;
	int result;
	result = build_elf_exec_info(buf, len, &ehdr, 0);
	if (result < 0) {
		goto out;
	}

	/* Verify the architecuture specific bits */
	if (ehdr.e_machine != EM_MIPS) {
		/* for a different architecture */
		if (probe_debug) {
			fprintf(stderr, "Not for this architecture.\n");
		}
		result = -1;
		goto out;
	}
	result = 0;
 out:
	free_elf_info(&ehdr);
	return result;
}

void elf_mipsel_usage(void)
{
	printf("    --command-line=STRING Set the kernel command line to "
			"STRING.\n"
	       "    --append=STRING       Set the kernel command line to "
			"STRING.\n");
}

int elf_mipsel_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info)
{
	struct mem_ehdr ehdr;
	char *arg_buf;
	size_t arg_bytes;
	unsigned long arg_base;
	struct boot_notes *notes;
	size_t note_bytes;
	const char *command_line;
	int command_line_len;
	unsigned char *setup_start;
	uint32_t setup_size;
	int opt;
#define OPT_APPEND     (OPT_ARCH_MAX+0)
	static const struct option options[] = {
		KEXEC_ARCH_OPTIONS
		{"command-line", 1, 0, OPT_APPEND},
		{"append",       1, 0, OPT_APPEND},
		{0, 0, 0, 0},
	};

	static const char short_options[] = KEXEC_ARCH_OPT_STR "d";

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
		}
	}
	command_line_len = 0;
	setup_simple_regs.spr9 = 0;
	if (command_line) {
		command_line_len = strlen(command_line) + 1;
		setup_simple_regs.spr9 = 2;
	}

	/* Load the ELF executable */
	elf_exec_build_load(info, &ehdr, buf, len, 0);

	setup_start = setup_simple_start;
	setup_size = setup_simple_size;
	setup_simple_regs.spr8 = ehdr.e_entry;

	note_bytes = sizeof(elf_boot_notes) + ((command_line_len + 3) & ~3);
	arg_bytes = note_bytes + ((setup_size + 3) & ~3);

	arg_buf = xmalloc(arg_bytes);
	arg_base = add_buffer_virt(info,
		 arg_buf, arg_bytes, arg_bytes, 4, 0, elf_max_addr(&ehdr), 1);

	notes = (struct boot_notes *)(arg_buf + ((setup_size + 3) & ~3));

	memcpy(arg_buf, setup_start, setup_size);
	memcpy(notes, &elf_boot_notes, sizeof(elf_boot_notes));
	memcpy(notes->command_line, command_line, command_line_len);

	notes->hdr.b_size = note_bytes;
	notes->cmd_hdr.n_descsz = command_line_len;
	notes->hdr.b_checksum = compute_ip_checksum(notes, note_bytes);

	info->entry = (void *)arg_base;

	return 0;
}

