/*
 * kexec/arch/s390/kexec-s390.c
 *
 * Copyright IBM Corp. 2005,2011
 *
 * Author(s): Rolf Adelsberger <adelsberger@de.ibm.com>
 *            Michael Holzheu <holzheu@linux.vnet.ibm.com>
 *
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include "../../kexec.h"
#include "../../kexec-syscall.h"
#include "kexec-s390.h"
#include <arch/options.h>

static struct memory_range memory_range[MAX_MEMORY_RANGES];

/*
 * Get memory ranges of type "System RAM" from /proc/iomem. If with_crashk=1
 * then also type "Crash kernel" is added.
 */
int get_memory_ranges_s390(struct memory_range memory_range[], int *ranges,
			   int with_crashk)
{
	char crash_kernel[] = "Crash kernel\n";
	char sys_ram[] = "System RAM\n";
	const char *iomem = proc_iomem();
	FILE *fp;
	char line[80];
	int current_range = 0;

	fp = fopen(iomem,"r");
	if(fp == 0) {
		fprintf(stderr,"Unable to open %s: %s\n",iomem,strerror(errno));
		return -1;
	}

	/* Setup the compare string properly. */
	while (fgets(line, sizeof(line), fp) != 0) {
		unsigned long long start, end;
		int cons;
		char *str;

		if (current_range == MAX_MEMORY_RANGES)
			break;

		sscanf(line,"%Lx-%Lx : %n", &start, &end, &cons);
		str = line+cons;
		if ((memcmp(str, sys_ram, strlen(sys_ram)) == 0) ||
		    ((memcmp(str, crash_kernel, strlen(crash_kernel)) == 0) &&
		     with_crashk)) {
			memory_range[current_range].start = start;
			memory_range[current_range].end = end;
			memory_range[current_range].type = RANGE_RAM;
			current_range++;
		}
		else {
			continue;
		}
	}
	fclose(fp);
	*ranges = current_range;
	return 0;
}

/*
 * get_memory_ranges:
 *  Return a list of memory ranges by parsing the file returned by
 *  proc_iomem()
 *
 * INPUT:
 *  - Pointer to an array of memory_range structures.
 *  - Pointer to an integer with holds the number of memory ranges.
 *
 * RETURN:
 *  - 0 on normal execution.
 *  - (-1) if something went wrong.
 */

int get_memory_ranges(struct memory_range **range, int *ranges,
		      unsigned long flags)
{
	uint64_t start, end;

	if (get_memory_ranges_s390(memory_range, ranges,
				   flags & KEXEC_ON_CRASH))
		return -1;
	*range = memory_range;
	if ((flags & KEXEC_ON_CRASH) && !(flags & KEXEC_PRESERVE_CONTEXT)) {
		if (parse_iomem_single("Crash kernel\n", &start, &end))
			return -1;
		if (start > mem_min)
			mem_min = start;
		if (end < mem_max)
			mem_max = end;
	}
	return 0;
}

/* Supported file types and callbacks */
struct file_type file_type[] = {
	{ "image", image_s390_probe, image_s390_load, image_s390_usage},
};
int file_types = sizeof(file_type) / sizeof(file_type[0]);


void arch_usage(void)
{
}

int arch_process_options(int UNUSED(argc), char **UNUSED(argv))
{
	return 0;
}

const struct arch_map_entry arches[] = {
	{ "s390", KEXEC_ARCH_S390 },
	{ "s390x", KEXEC_ARCH_S390 },
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
	uint64_t start, end;

	return parse_iomem_single("Crash kernel\n", &start, &end) == 0 ?
		(start != end) : 0;
}
