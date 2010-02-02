/*
 * kexec-ppc.c - kexec for the PowerPC
 * Copyright (C) 2004, 2005 Albert Herranz
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include "../../kexec.h"
#include "../../kexec-syscall.h"
#include "kexec-ppc.h"
#include <arch/options.h>

#include "config.h"

#ifdef WITH_GAMECUBE
#define MAX_MEMORY_RANGES  64
static struct memory_range memory_range[MAX_MEMORY_RANGES];
#endif

/* Return a sorted list of memory ranges. */
int get_memory_ranges(struct memory_range **UNUSED(range), int *UNUSED(ranges),
		      unsigned long UNUSED(kexec_flags))
{
#ifdef WITH_GAMECUBE
	int memory_ranges = 0;

	/* RAM - lowmem used by DOLs - framebuffer */
	memory_range[memory_ranges].start = 0x00003000;
	memory_range[memory_ranges].end = 0x0174bfff;
	memory_range[memory_ranges].type = RANGE_RAM;
	memory_ranges++;
	*range = memory_range;
	*ranges = memory_ranges;
	return 0;
#else
	fprintf(stderr, "%s(): Unsupported platform\n", __func__);
	return -1;
#endif
}

struct file_type file_type[] = {
	{"elf-ppc", elf_ppc_probe, elf_ppc_load, elf_ppc_usage},
	{"dol-ppc", dol_ppc_probe, dol_ppc_load, dol_ppc_usage},
};
int file_types = sizeof(file_type) / sizeof(file_type[0]);

void arch_usage(void)
{
}

int arch_process_options(int argc, char **argv)
{
	static const struct option options[] = {
		KEXEC_ARCH_OPTIONS
		{ 0, 			0, NULL, 0 },
	};
	static const char short_options[] = KEXEC_ARCH_OPT_STR;
	int opt;

	opterr = 0; /* Don't complain about unrecognized options here */
	while((opt = getopt_long(argc, argv, short_options, options, 0)) != -1) {
		switch(opt) {
		default:
			break;
		}
	}
	/* Reset getopt for the next pass; called in other source modules */
	opterr = 1;
	optind = 1;
	return 0;
}

const struct arch_map_entry arches[] = {
	/* For compatibility with older patches
	 * use KEXEC_ARCH_DEFAULT instead of KEXEC_ARCH_PPC here.
	 */
	{ "ppc", KEXEC_ARCH_DEFAULT },
	{ NULL, 0 },
};

int arch_compat_trampoline(struct kexec_info *UNUSED(info))
{
	return 0;
}

void arch_update_purgatory(struct kexec_info *UNUSED(info))
{
}

int is_crashkernel_mem_reserved(void)
{
	return 0; /* kdump is not supported on this platform (yet) */
}
