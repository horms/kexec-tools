/*
 * kexec: Linux boots Linux
 *
 * Copyright (C) 2004  Adam Litke (agl@us.ibm.com)
 * Copyright (C) 2004  IBM Corp.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <linux/elf.h>
#include "../../kexec.h"
#include "../../kexec-elf.h"
#include "kexec-ppc64.h"

#define BOOTLOADER         "kexec"
#define BOOTLOADER_VERSION VERSION
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

int elf_ppc64_probe(const char *buf, off_t len)
{
	struct mem_ehdr ehdr;
	int result;
	result = build_elf_exec_info(buf, len, &ehdr);
	if (result < 0) {
		goto out;
	}

	/* Verify the architecuture specific bits */
	if ((ehdr.e_machine != EM_PPC64) && (ehdr.e_machine != EM_PPC)) {
		/* for a different architecture */
		result = -1;
		goto out;
	}
	result = 0;
 out:
	free_elf_info(&ehdr);
	return result;
}

int elf_ppc64_load(int argc, char **argv, const char *buf, off_t len, 
	struct kexec_info *info)
{
	struct mem_ehdr ehdr;

	/* Parse command line arguments */

	/* Parse the Elf file */
	result = build_elf_exec_info(buf, len, &ehdr);
	if (result < 0) {
		free_elf_info(&ehdr);
		return result;
	}

	/* Load the Elf data */
	result = elf_exec_load(&ehdr, info);
	if (result < 0) {
		free_elf_info(&ehdr);
		return result;
	}
	return 1;
}

void elf_ppc64_usage(void)
{
	fprintf(stderr, "elf support is still broken\n");
}
