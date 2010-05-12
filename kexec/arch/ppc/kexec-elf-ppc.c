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
#include <limits.h>
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
#include "../../kexec-syscall.h"
#include "crashdump-powerpc.h"

#include "config.h"
#include "fixup_dtb.h"

static const int probe_debug = 0;

unsigned long long initrd_base, initrd_size;
unsigned char reuse_initrd;
const char *ramdisk;
int create_flatten_tree(struct kexec_info *, unsigned char **, unsigned long *,
			char *);

#define UPSZ(X) ((sizeof(X) + 3) & ~3)
#ifdef WITH_GAMECUBE
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
#endif

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

#ifdef WITH_GAMECUBE
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
#endif

#define OPT_APPEND	(OPT_ARCH_MAX+0)
#define OPT_GAMECUBE	(OPT_ARCH_MAX+1)
#define OPT_DTB		(OPT_ARCH_MAX+2)
#define OPT_NODES	(OPT_ARCH_MAX+3)
static const struct option options[] = {
	KEXEC_ARCH_OPTIONS
	{"command-line", 1, 0, OPT_APPEND},
	{"append",       1, 0, OPT_APPEND},
	{"gamecube",     1, 0, OPT_GAMECUBE},
	{"dtb",     1, 0, OPT_DTB},
	{"reuse-node",     1, 0, OPT_NODES},
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
	     "     --dtb=<filename>     Specify device tree blob file.\n"
	     "     --reuse-node=node    Specify nodes which should be taken from /proc/device-tree.\n"
	     "                          Can be set multiple times.\n"
	     );
}

int elf_ppc_load(int argc, char **argv,	const char *buf, off_t len, 
	struct kexec_info *info)
{
	struct mem_ehdr ehdr;
	char *command_line, *crash_cmdline, *cmdline_buf;
	int command_line_len;
	char *dtb;
	int result;
	unsigned long max_addr, hole_addr;
	struct mem_phdr *phdr;
	size_t size;
	unsigned long long *rsvmap_ptr;
	struct bootblock *bb_ptr;
	unsigned int nr_segments;
	unsigned long my_kernel, my_dt_offset;
	unsigned long my_stack, my_backup_start;
#ifdef CONFIG_PPC64
	unsigned long toc_addr;
#endif
	unsigned int slave_code[256 / sizeof(unsigned int)], master_entry;
	unsigned char *seg_buf = NULL;
	off_t seg_size = 0;
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
#define FIXUP_ENTRYS	(20)
	char *fixup_nodes[FIXUP_ENTRYS + 1];
	int cur_fixup = 0;
#endif
	int opt;

	command_line = NULL;
	dtb = NULL;
	max_addr = LONG_MAX;
	hole_addr = 0;

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

		case OPT_NODES:
			if (cur_fixup >= FIXUP_ENTRYS) {
				fprintf(stderr, "The number of entries for the fixup is too large\n");
				exit(1);
			}
			fixup_nodes[cur_fixup] = optarg;
			cur_fixup++;
			break;
		}
	}

	command_line_len = 0;
	if (command_line) {
		command_line_len = strlen(command_line) + 1;
	}

	fixup_nodes[cur_fixup] = NULL;

	/* Need to append some command line parameters internally in case of
	 * taking crash dumps.
	 */
	if (info->kexec_flags & KEXEC_ON_CRASH) {
		crash_cmdline = xmalloc(COMMAND_LINE_SIZE);
		memset((void *)crash_cmdline, 0, COMMAND_LINE_SIZE);
	} else
		crash_cmdline = NULL;

	/* Parse the Elf file */
	result = build_elf_exec_info(buf, len, &ehdr, 0);
	if (result < 0) {
		free_elf_info(&ehdr);
		return result;
	}

#ifdef WITH_GAMECUBE
	if (target_is_gamecube) {
		gamecube_hack_addresses(&ehdr);
	}
#endif

	/* Load the Elf data. Physical load addresses in elf64 header do not
	 * show up correctly. Use user supplied address for now to patch the
	 * elf header
	 */

	phdr = &ehdr.e_phdr[0];
	size = phdr->p_filesz;
	if (size > phdr->p_memsz)
		size = phdr->p_memsz;

	hole_addr = locate_hole(info, size, 0, 0, max_addr, 1);
#ifdef CONFIG_PPC64
	ehdr.e_phdr[0].p_paddr = (Elf64_Addr)hole_addr;
#else
	ehdr.e_phdr[0].p_paddr = hole_addr;
#endif

	/* Load the Elf data */
	result = elf_exec_load(&ehdr, info);
	if (result < 0) {
		free_elf_info(&ehdr);
		return result;
	}

	/* If panic kernel is being loaded, additional segments need
	 * to be created.
	 */
	if (info->kexec_flags & KEXEC_ON_CRASH) {
		result = load_crashdump_segments(info, crash_cmdline,
						max_addr, 0);
		if (result < 0) {
			free(crash_cmdline);
			return -1;
		}
	}

	cmdline_buf = xmalloc(COMMAND_LINE_SIZE);
	memset((void *)cmdline_buf, 0, COMMAND_LINE_SIZE);
	if (command_line)
		strncat(cmdline_buf, command_line, command_line_len);
	if (crash_cmdline)
		strncat(cmdline_buf, crash_cmdline,
				sizeof(crash_cmdline) -
				strlen(crash_cmdline) - 1);

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
		if (!blob_buf || !blob_size)
			die("Device tree seems to be an empty file.\n");
		blob_buf = fixup_dtb_nodes(blob_buf, &blob_size, fixup_nodes,
				cmdline_buf);
		dtb_addr = add_buffer(info, blob_buf, blob_size, blob_size, 0, 0,
				KERNEL_ACCESS_TOP, -1);
	} else {
		/* create from fs2dt */
		seg_buf = NULL;
		seg_size = 0;
		create_flatten_tree(info, (unsigned char **)&seg_buf,
				(unsigned long *)&seg_size, cmdline_buf);
		add_buffer(info, seg_buf, seg_size, seg_size,
#ifdef CONFIG_PPC64
				0, 0,  max_addr, -1);
#else
		/* load dev tree at 16 Mb offset from kernel load address */
			0, 0, ehdr.e_phdr[0].p_paddr + SIZE_16M, -1);
#endif
	}


	if (dtb) {
		/* set various variables for the purgatory */
		addr = ehdr.e_entry;
		elf_rel_set_symbol(&info->rhdr, "kernel", &addr, sizeof(addr));

		addr = dtb_addr;
		elf_rel_set_symbol(&info->rhdr, "dt_offset",
						&addr, sizeof(addr));

		addr = rmo_top;

		elf_rel_set_symbol(&info->rhdr, "mem_size",
						&addr, sizeof(addr));

#define PUL_STACK_SIZE	(16 * 1024)
		addr = locate_hole(info, PUL_STACK_SIZE, 0, 0,
				elf_max_addr(&ehdr), 1);
		addr += PUL_STACK_SIZE;
		elf_rel_set_symbol(&info->rhdr, "stack", &addr, sizeof(addr));
#undef PUL_STACK_SIZE

		addr = elf_rel_get_addr(&info->rhdr, "purgatory_start");
		info->entry = (void *)addr;

	} else { /*from fs2dt*/

		/* patch reserve map address for flattened device-tree
		 * find last entry (both 0) in the reserve mem list.  Assume DT
		 * entry is before this one
		 */
		bb_ptr = (struct bootblock *)(
			(unsigned char *)info->segment[(info->nr_segments) -
				1].buf);
		rsvmap_ptr = (unsigned long long *)(
			(unsigned char *)info->segment[(info->nr_segments) -
				1].buf + bb_ptr->off_mem_rsvmap);
		while (*rsvmap_ptr || *(rsvmap_ptr + 1))
			rsvmap_ptr += 2;
		rsvmap_ptr -= 2;
		*rsvmap_ptr = (unsigned long)(
				info->segment[(info->nr_segments)-1].mem);
		rsvmap_ptr++;
		*rsvmap_ptr = (unsigned long long)bb_ptr->totalsize;

		nr_segments = info->nr_segments;

		/* Set kernel */
		my_kernel = (unsigned long)info->segment[0].mem;
		elf_rel_set_symbol(&info->rhdr, "kernel", &my_kernel,
				sizeof(my_kernel));

		/* Set dt_offset */
		my_dt_offset = (unsigned long)info->segment[nr_segments -
			1].mem;
		elf_rel_set_symbol(&info->rhdr, "dt_offset", &my_dt_offset,
				sizeof(my_dt_offset));

		/* get slave code from new kernel, put in purgatory */
		elf_rel_get_symbol(&info->rhdr, "purgatory_start", slave_code,
				sizeof(slave_code));
		master_entry = slave_code[0];
		memcpy(slave_code, info->segment[0].buf, sizeof(slave_code));
		slave_code[0] = master_entry;
		elf_rel_set_symbol(&info->rhdr, "purgatory_start", slave_code,
				sizeof(slave_code));

		/* Set stack address */
		my_stack = locate_hole(info, 16*1024, 0, 0, max_addr, 1);
		my_stack += 16*1024;
		elf_rel_set_symbol(&info->rhdr, "stack", &my_stack,
				sizeof(my_stack));
	}

	if (info->kexec_flags & KEXEC_ON_CRASH) {
		/* Set backup address */
		my_backup_start = info->backup_start;
		elf_rel_set_symbol(&info->rhdr, "backup_start",
				&my_backup_start, sizeof(my_backup_start));
	}
#endif
	return 0;
}
