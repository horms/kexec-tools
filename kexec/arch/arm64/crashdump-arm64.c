/*
 * ARM64 crashdump.
 *     partly derived from arm implementation
 *
 * Copyright (c) 2014-2017 Linaro Limited
 * Author: AKASHI Takahiro <takahiro.akashi@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <linux/elf.h>

#include "kexec.h"
#include "crashdump.h"
#include "crashdump-arm64.h"
#include "iomem.h"
#include "kexec-arm64.h"
#include "kexec-elf.h"
#include "mem_regions.h"

/* memory ranges on crashed kernel */
static struct memory_range system_memory_ranges[CRASH_MAX_MEMORY_RANGES];
static struct memory_ranges system_memory_rgns = {
	.size = 0,
	.max_size = CRASH_MAX_MEMORY_RANGES,
	.ranges = system_memory_ranges,
};

/* memory range reserved for crashkernel */
struct memory_range crash_reserved_mem;
struct memory_ranges usablemem_rgns = {
	.size = 0,
	.max_size = 1,
	.ranges = &crash_reserved_mem,
};

/*
 * iomem_range_callback() - callback called for each iomem region
 * @data: not used
 * @nr: not used
 * @str: name of the memory region
 * @base: start address of the memory region
 * @length: size of the memory region
 *
 * This function is called once for each memory region found in /proc/iomem.
 * It locates system RAM and crashkernel reserved memory and places these to
 * variables, respectively, system_memory_ranges and crash_reserved_mem.
 */

static int iomem_range_callback(void *UNUSED(data), int UNUSED(nr),
				char *str, unsigned long long base,
				unsigned long long length)
{
	if (strncmp(str, CRASH_KERNEL, strlen(CRASH_KERNEL)) == 0)
		return mem_regions_add(&usablemem_rgns,
				       base, length, RANGE_RAM);
	else if (strncmp(str, SYSTEM_RAM, strlen(SYSTEM_RAM)) == 0)
		return mem_regions_add(&system_memory_rgns,
				       base, length, RANGE_RAM);

	return 0;
}

int is_crashkernel_mem_reserved(void)
{
	if (!usablemem_rgns.size)
		kexec_iomem_for_each_line(NULL, iomem_range_callback, NULL);

	return crash_reserved_mem.start != crash_reserved_mem.end;
}

/*
 * crash_get_memory_ranges() - read system physical memory
 *
 * Function reads through system physical memory and stores found memory
 * regions in system_memory_ranges.
 * Regions are sorted in ascending order.
 *
 * Returns 0 in case of success and a negative value otherwise.
 */
static int crash_get_memory_ranges(void)
{
	/*
	 * First read all memory regions that can be considered as
	 * system memory including the crash area.
	 */
	if (!usablemem_rgns.size)
		kexec_iomem_for_each_line(NULL, iomem_range_callback, NULL);

	/* allow only a single region for crash dump kernel */
	if (usablemem_rgns.size != 1)
		return -EINVAL;

	dbgprint_mem_range("Reserved memory range", &crash_reserved_mem, 1);

	if (mem_regions_exclude(&system_memory_rgns, &crash_reserved_mem)) {
		fprintf(stderr,
			"Error: Number of crash memory ranges excedeed the max limit\n");
		return -ENOMEM;
	}

	/*
	 * Make sure that the memory regions are sorted.
	 */
	mem_regions_sort(&system_memory_rgns);

	dbgprint_mem_range("Coredump memory ranges",
			   system_memory_rgns.ranges, system_memory_rgns.size);
}

int get_crash_kernel_load_range(uint64_t *start, uint64_t *end)
{
	if (!usablemem_rgns.size)
		kexec_iomem_for_each_line(NULL, iomem_range_callback, NULL);

	if (!crash_reserved_mem.end)
		return -1;

	*start = crash_reserved_mem.start;
	*end = crash_reserved_mem.end;

	return 0;
}
