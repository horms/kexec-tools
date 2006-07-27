/*
 * kexec: Linux boots Linux
 *
 * Copyright (C) 2003-2005  Eric Biederman (ebiederm@xmission.com)
 * Copyright (C) 2004 Albert Herranz
 * Copyright (C) 2004 Silicon Graphics, Inc.
 *   Jesse Barnes <jbarnes@sgi.com>
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
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <sched.h>
#include <sys/utsname.h>
#include "../../kexec.h"
#include "../../kexec-syscall.h"
#include "kexec-ia64.h"
#include <arch/options.h>

static struct memory_range memory_range[MAX_MEMORY_RANGES];

/* Return a sorted list of available memory ranges. */
int get_memory_ranges(struct memory_range **range, int *ranges,
				unsigned long kexec_flags)
{
	const char iomem[]= "/proc/iomem";
	int memory_ranges = 0;
	char line[MAX_LINE];
	FILE *fp;
	fp = fopen(iomem, "r");
	if (!fp) {
		fprintf(stderr, "Cannot open %s: %s\n",
			iomem, strerror(errno));
		return -1;
	}

	while(fgets(line, sizeof(line), fp) != 0) {
		unsigned long start, end;
		char *str;
		int type;
		int consumed;
		int count;
		if (memory_ranges >= MAX_MEMORY_RANGES)
			break;
		count = sscanf(line, "%lx-%lx : %n",
				&start, &end, &consumed);
		if (count != 2)
			continue;
		str = line + consumed;
		end = end + 1;
		if (memcmp(str, "System RAM\n", 11) == 0) {
			type = RANGE_RAM;
		}
		else if (memcmp(str, "reserved\n", 9) == 0) {
			type = RANGE_RESERVED;
		}
		else if (memcmp(str, "Crash kernel\n", 13) == 0) {
			/* Redefine the memory region boundaries if kernel
			 * exports the limits and if it is panic kernel.
			 * Override user values only if kernel exported
			 * values are subset of user defined values.
			 */

			if (kexec_flags & KEXEC_ON_CRASH) {
				if (start > mem_min)
					mem_min = start;
				if (end < mem_max)
					mem_max = end;
			}
			continue;
		} else
			continue;
		/*
		 * Check if this memory range can be coalesced with
		 * the previous range
		 */
		if ((memory_ranges > 0) &&
			(start == memory_range[memory_ranges-1].end) &&
			(type == memory_range[memory_ranges-1].type)) {
			memory_range[memory_ranges-1].end = end;
		}
		else {
			memory_range[memory_ranges].start = start;
			memory_range[memory_ranges].end = end;
			memory_range[memory_ranges].type = type;
			memory_ranges++;
		}
	}
	fclose(fp);
 	*range = memory_range;
 	*ranges = memory_ranges;

 	return 0;
}

/* Supported file types and callbacks */
struct file_type file_type[] = {
       {"elf-ia64", elf_ia64_probe, elf_ia64_load, elf_ia64_usage},
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

	/* execute from monarch processor */
        cpu_set_t affinity;
	CPU_ZERO(&affinity);
	CPU_SET(0, &affinity);
        sched_setaffinity(0, sizeof(affinity), &affinity);

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

int arch_compat_trampoline(struct kexec_info *info)
{
	int result;
	struct utsname utsname;
	result = uname(&utsname);
	if (result < 0) {
		fprintf(stderr, "uname failed: %s\n",
			strerror(errno));
		return -1;
	}
	if (strcmp(utsname.machine, "ia64") == 0)
	{
		info->kexec_flags |= KEXEC_ARCH_IA_64;
	}
	else {
		fprintf(stderr, "Unsupported machine type: %s\n",
			utsname.machine);
		return -1;
	}
	return 0;
}

void arch_update_purgatory(struct kexec_info *info)
{
}

