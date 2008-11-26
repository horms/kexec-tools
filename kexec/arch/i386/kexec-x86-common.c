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

#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include "../../kexec.h"
#include "../../kexec-syscall.h"
#include "../../firmware_memmap.h"
#include "../../crashdump.h"
#include "kexec-x86.h"

static struct memory_range memory_range[MAX_MEMORY_RANGES];

/**
 * The old /proc/iomem parsing code.
 *
 * @param[out] range pointer that will be set to an array that holds the
 *             memory ranges
 * @param[out] ranges number of ranges valid in @p range
 *
 * @return 0 on success, any other value on failure.
 */
static int get_memory_ranges_proc_iomem(struct memory_range **range, int *ranges)
{
	const char *iomem= proc_iomem();
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
		unsigned long long start, end;
		char *str;
		int type;
		int consumed;
		int count;
		if (memory_ranges >= MAX_MEMORY_RANGES)
			break;
		count = sscanf(line, "%Lx-%Lx : %n",
			&start, &end, &consumed);
		if (count != 2)
			continue;
		str = line + consumed;
		end = end + 1;
#if 0
		printf("%016Lx-%016Lx : %s",
			start, end, str);
#endif
		if (memcmp(str, "System RAM\n", 11) == 0) {
			type = RANGE_RAM;
		}
		else if (memcmp(str, "reserved\n", 9) == 0) {
			type = RANGE_RESERVED;
		}
		else if (memcmp(str, "ACPI Tables\n", 12) == 0) {
			type = RANGE_ACPI;
		}
		else if (memcmp(str, "ACPI Non-volatile Storage\n", 26) == 0) {
			type = RANGE_ACPI_NVS;
		}
		else {
			continue;
		}
		memory_range[memory_ranges].start = start;
		memory_range[memory_ranges].end = end;
		memory_range[memory_ranges].type = type;
#if 0
		printf("%016Lx-%016Lx : %x\n",
			start, end, type);
#endif
		memory_ranges++;
	}
	fclose(fp);
	*range = memory_range;
	*ranges = memory_ranges;
	return 0;
}

/**
 * Calls the architecture independent get_firmware_memmap_ranges() to parse
 * /sys/firmware/memmap and then do some x86 only modifications.
 *
 * @param[out] range pointer that will be set to an array that holds the
 *             memory ranges
 * @param[out] ranges number of ranges valid in @p range
 *
 * @return 0 on success, any other value on failure.
 */
static int get_memory_ranges_sysfs(struct memory_range **range, int *ranges)
{
	int ret;
	size_t range_number = MAX_MEMORY_RANGES;

	ret = get_firmware_memmap_ranges(memory_range, &range_number);
	if (ret != 0) {
		fprintf(stderr, "Parsing the /sys/firmware memory map failed. "
			"Falling back to /proc/iomem.\n");
		return get_memory_ranges_proc_iomem(range, ranges);
	}

	*range = memory_range;
	*ranges = range_number;

	return 0;
}

/**
 * Return a sorted list of memory ranges.
 *
 * If we have the /sys/firmware/memmap interface, then use that. If not,
 * or if parsing of that fails, use /proc/iomem as fallback.
 *
 * @param[out] range pointer that will be set to an array that holds the
 *             memory ranges
 * @param[out] ranges number of ranges valid in @p range
 * @param[in]  kexec_flags the kexec_flags to determine if we load a normal
 *             or a crashdump kernel
 *
 * @return 0 on success, any other value on failure.
 */
int get_memory_ranges(struct memory_range **range, int *ranges,
		      unsigned long kexec_flags)
{
	int ret, i;

	/*
	 * When using Xen, /sys/firmware/memmap (i.e., the E820 map) is
	 * wrong, it just provides one large memory are and that cannot
	 * be used for Kdump. Use always the /proc/iomem interface there
	 * even if we have /sys/firmware/memmap. Without that, /proc/vmcore
	 * is empty in the kdump kernel.
	 */
	if (!xen_present() && have_sys_firmware_memmap())
		ret = get_memory_ranges_sysfs(range, ranges);
	else
		ret = get_memory_ranges_proc_iomem(range, ranges);

	/*
	 * both get_memory_ranges_sysfs() and get_memory_ranges_proc_iomem()
	 * have already printed an error message, so fail silently here
	 */
	if (ret != 0)
		return ret;

	/* Don't report the interrupt table as ram */
	for (i = 0; i < *ranges; i++) {
		if ((*range)[i].type == RANGE_RAM &&
				((*range)[i].start < 0x100)) {
			(*range)[i].start = 0x100;
			break;
		}
	}

	/*
	 * Redefine the memory region boundaries if kernel
	 * exports the limits and if it is panic kernel.
	 * Override user values only if kernel exported values are
	 * subset of user defined values.
	 */
	if ((kexec_flags & KEXEC_ON_CRASH) &&
	    !(kexec_flags & KEXEC_PRESERVE_CONTEXT)) {
		unsigned long long start, end;

		ret = parse_iomem_single("Crash kernel\n", &start, &end);
		if (ret != 0) {
			fprintf(stderr, "parse_iomem_single failed.\n");
			return -1;
		}

		if (start > mem_min)
			mem_min = start;
		if (end < mem_max)
			mem_max = end;
	}

	/* just set 0 to 1 to enable printing for debugging */
#if 0
	{
		int i;
		printf("MEMORY RANGES\n");
		for (i = 0; i < *ranges; i++) {
			printf("%016Lx-%016Lx (%d)\n", (*range)[i].start,
				(*range)[i].end, (*range)[i].type);
		}
	}
#endif

	return ret;
}


