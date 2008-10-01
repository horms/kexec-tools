/*
 * kexec-elf-ppc.c - kexec Elf loader for the PowerPC
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
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <elf.h>
#include <boot/elf_boot.h>
#include <ip_checksum.h>
#include "../../kexec.h"
#include "../../kexec-elf.h"
#include "kexec-ppc.h"
#include <arch/options.h>

#include "config.h"

static const int probe_debug = 0;

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


int elf_ppc_probe(const char *buf, off_t len)
{

	struct mem_ehdr ehdr;
	int result;
	result = build_elf_exec_info(buf, len, &ehdr, 0);
	if (result < 0) {
		goto out;
	}
	
	/* Verify the architecuture specific bits */
	if (ehdr.e_machine != EM_PPC) {
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

static void gamecube_hack_addresses(struct mem_ehdr *ehdr)
{
	struct mem_phdr *phdr, *phdr_end;
	phdr_end = ehdr->e_phdr + ehdr->e_phnum;
	for(phdr = ehdr->e_phdr; phdr != phdr_end; phdr++) {
		/*
		 * GameCube ELF kernel is linked with memory mapped
		 * this way (to easily transform it into a DOL
		 * suitable for being loaded with psoload):
		 *
		 * 80000000 - 817fffff 24MB RAM, cached
		 * c0000000 - c17fffff 24MB RAM, not cached
		 *
		 * kexec, instead, needs physical memory layout, so
		 * we clear the upper bits of the address.
		 * (2 bits should be enough, indeed)
		 */
		phdr->p_paddr &= ~0xf0000000;	/* clear bits 0-3, ibm syntax */
	}
}

#define OPT_APPEND	(OPT_ARCH_MAX+0)
#define OPT_GAMECUBE	(OPT_ARCH_MAX+1)
#define OPT_DTB		(OPT_ARCH_MAX+2)
static const struct option options[] = {
	KEXEC_ARCH_OPTIONS
	{"command-line", 1, 0, OPT_APPEND},
	{"append",       1, 0, OPT_APPEND},
	{"gamecube",     1, 0, OPT_GAMECUBE},
	{"dtb",     1, 0, OPT_DTB},
	{0, 0, 0, 0},
};
static const char short_options[] = KEXEC_ARCH_OPT_STR "d";

void elf_ppc_usage(void)
{
	printf(
	     "    --command-line=STRING Set the kernel command line to STRING.\n"
	     "    --append=STRING       Set the kernel command line to STRING.\n"
	     "    --gamecube=1|0        Enable/disable support for ELFs with changed\n"
	     "                          addresses suitable for the GameCube.\n"
	     "     --dtb=<filename> Specify device tree blob file.\n"
	     );
}

int elf_ppc_load(int argc, char **argv,	const char *buf, off_t len, 
	struct kexec_info *info)
{
	struct mem_ehdr ehdr;
	char *command_line;
	int command_line_len;
	char *dtb;
	int result;
#ifdef WITH_GAMECUBE
	int target_is_gamecube = 1;
	char *arg_buf;
	size_t arg_bytes;
	unsigned long arg_base;
	struct boot_notes *notes;
	size_t note_bytes;
	unsigned char *setup_start;
	uint32_t setup_size;
#else
	int target_is_gamecube = 0;
	unsigned int addr;
	unsigned long dtb_addr;
#endif
	int opt;

	command_line = NULL;
	dtb = NULL;
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
		case OPT_GAMECUBE:
			target_is_gamecube = atoi(optarg);
			break;

		case OPT_DTB:
			dtb = optarg;
			break;
		}
	}
	command_line_len = 0;
	if (command_line) {
		command_line_len = strlen(command_line) + 1;
	}

	/* Parse the Elf file */
	result = build_elf_exec_info(buf, len, &ehdr, 0);
	if (result < 0) {
		free_elf_info(&ehdr);
		return result;
	}
	if (target_is_gamecube) {
		gamecube_hack_addresses(&ehdr);
	}
	/* Load the Elf data */
	result = elf_exec_load(&ehdr, info);
	if (result < 0) {
		free_elf_info(&ehdr);
		return result;
	}

	/*
	 * In case of a toy we take the hardcoded things and an easy setup via
	 * one of the assembly startups. Every thing else should be grown up
	 * and go through the purgatory.
	 */
#ifdef WITH_GAMECUBE
	if (target_is_gamecube) {
		setup_start = setup_dol_start;
		setup_size = setup_dol_size;
		setup_dol_regs.spr8 = ehdr.e_entry;	/* Link Register */
	} else {
		setup_start = setup_simple_start;
		setup_size = setup_simple_size;
		setup_simple_regs.spr8 = ehdr.e_entry;	/* Link Register */
	}
	note_bytes = sizeof(elf_boot_notes) + ((command_line_len + 3) & ~3);
	arg_bytes = note_bytes + ((setup_size + 3) & ~3);

	arg_buf = xmalloc(arg_bytes);
	arg_base = add_buffer(info, 
		arg_buf, arg_bytes, arg_bytes, 4, 0, elf_max_addr(&ehdr), 1);

	notes = (struct boot_notes *)(arg_buf + ((setup_size + 3) & ~3));

	memcpy(arg_buf, setup_start, setup_size);
	memcpy(notes, &elf_boot_notes, sizeof(elf_boot_notes));
	memcpy(notes->command_line, command_line, command_line_len);
	notes->hdr.b_size = note_bytes;
	notes->cmd_hdr.n_descsz = command_line_len;
	notes->hdr.b_checksum = compute_ip_checksum(notes, note_bytes);

	info->entry = (void *)arg_base;
#else
	elf_rel_build_load(info, &info->rhdr, (const char *)purgatory,
			purgatory_size, 0, elf_max_addr(&ehdr), 1, 0);

	if (dtb) {
		char *blob_buf;
		off_t blob_size = 0;

		/* Grab device tree from buffer */
		blob_buf = slurp_file(dtb, &blob_size);
		dtb_addr = add_buffer(info, blob_buf, blob_size, blob_size, 0, 0,
				KERNEL_ACCESS_TOP, -1);
		if (command_line)
			die("Don't consider command line because dtb is supplied\n");
	} else {
		die("Missing dtb.\n");
	}

	/* set various variables for the purgatory */
	addr = ehdr.e_entry;
	elf_rel_set_symbol(&info->rhdr, "kernel", &addr, sizeof(addr));

	addr = dtb_addr;
	elf_rel_set_symbol(&info->rhdr, "dt_offset", &addr, sizeof(addr));

	addr = rmo_top;
	elf_rel_set_symbol(&info->rhdr, "mem_size", &addr, sizeof(addr));

#define PUL_STACK_SIZE	(16 * 1024)
	addr = locate_hole(info, PUL_STACK_SIZE, 0, 0, elf_max_addr(&ehdr), 1);
	addr += PUL_STACK_SIZE;
	elf_rel_set_symbol(&info->rhdr, "pul_stack", &addr, sizeof(addr));
#undef PUL_STACK_SIZE

	addr = elf_rel_get_addr(&info->rhdr, "purgatory_start");
	info->entry = (void *)addr;
#endif
	return 0;
}
