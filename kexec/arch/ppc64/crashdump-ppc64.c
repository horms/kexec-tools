/*
 * kexec: Linux boots Linux
 *
 * Created by: R Sharada (sharada@in.ibm.com)
 * Copyright (C) IBM Corporation, 2005. All rights reserved
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <elf.h>
#include <dirent.h>
#include "../../kexec.h"
#include "../../kexec-elf.h"
#include "../../kexec-syscall.h"
#include "../../crashdump.h"
#include "kexec-ppc64.h"
#include "crashdump-ppc64.h"

/* Stores a sorted list of RAM memory ranges for which to create elf headers.
 * A separate program header is created for backup region
 */
static struct memory_range crash_memory_range[CRASH_MAX_MEMORY_RANGES];

/*
 * Used to save various memory ranges/regions needed for the captured
 * kernel to boot. (lime memmap= option in other archs)
 */
mem_rgns_t usablemem_rgns = {0, };

/* array to store memory regions to be excluded from elf header creation */
mem_rgns_t exclude_rgns = {0, };

static int sort_regions(mem_rgns_t *rgn);

/* Reads the appropriate file and retrieves the SYSTEM RAM regions for whom to
 * create Elf headers. Keeping it separate from get_memory_ranges() as
 * requirements are different in the case of normal kexec and crashdumps.
 *
 * Normal kexec needs to look at all of available physical memory irrespective
 * of the fact how much of it is being used by currently running kernel.
 * Crashdumps need to have access to memory regions actually being used by
 * running  kernel. Expecting a different file/data structure than /proc/iomem
 * to look into down the line. May be something like /proc/kernelmem or may
 * be zone data structures exported from kernel.
 */
static int get_crash_memory_ranges(struct memory_range **range, int *ranges)
{

	int memory_ranges = 0;
	char device_tree[256] = "/proc/device-tree/";
	char fname[256];
	char buf[MAXBYTES-1];
	DIR *dir, *dmem;
	FILE *file;
	struct dirent *dentry, *mentry;
	int i, n, match;
	unsigned long long start, end, cstart, cend;

	/* create a separate program header for the backup region */
	crash_memory_range[0].start = 0x0000000000000000;
	crash_memory_range[0].end = 0x0000000000008000;
	crash_memory_range[0].type = RANGE_RAM;
	memory_ranges++;

	if ((dir = opendir(device_tree)) == NULL) {
		perror(device_tree);
		return -1;
	}
	while ((dentry = readdir(dir)) != NULL) {
		if (strncmp(dentry->d_name, "memory@", 7))
			continue;
		strcpy(fname, device_tree);
		strcat(fname, dentry->d_name);
		if ((dmem = opendir(fname)) == NULL) {
			perror(fname);
			closedir(dir);
			return -1;
		}
		while ((mentry = readdir(dmem)) != NULL) {
			if (strcmp(mentry->d_name, "reg"))
				continue;
			strcat(fname, "/reg");
			if ((file = fopen(fname, "r")) == NULL) {
				perror(fname);
				closedir(dmem);
				closedir(dir);
				return -1;
			}
			if ((n = fread(buf, 1, MAXBYTES, file)) < 0) {
				perror(fname);
				fclose(file);
				closedir(dmem);
				closedir(dir);
				return -1;
			}
			if (memory_ranges >= MAX_MEMORY_RANGES)
				break;
			start = ((unsigned long long *)buf)[0];
			end = start + ((unsigned long long *)buf)[1];
			if (start == 0 && end >= 0x8000)
				start = 0x8000;
			match = 0;
			sort_regions(&exclude_rgns);

			/* exclude crash reserved regions */
			for (i = 0; i < exclude_rgns.size; i++) {
				cstart = exclude_rgns.ranges[i].start;
				cend = exclude_rgns.ranges[i].end;
				if (cstart < end && cend > start) {
					if ((cstart == start) && (cend == end)) {
						match = 1;
						continue;
					}
					if (start < cstart && end > cend) {
						match = 1;
						crash_memory_range[memory_ranges].start = start;
						crash_memory_range[memory_ranges].end = cstart - 1;
						crash_memory_range[memory_ranges].type = RANGE_RAM;
						memory_ranges++;
						crash_memory_range[memory_ranges].start = cend + 1;
						crash_memory_range[memory_ranges].end = end;
						crash_memory_range[memory_ranges].type = RANGE_RAM;
						memory_ranges++;
						break;
					} else if (start < cstart) {
						match = 1;
						crash_memory_range[memory_ranges].start = start;
						crash_memory_range[memory_ranges].end = cstart - 1;
						crash_memory_range[memory_ranges].type = RANGE_RAM;
						memory_ranges++;
						end = cstart - 1;
						continue;
					} else if (end > cend){
						match = 1;
						crash_memory_range[memory_ranges].start = cend + 1;
						crash_memory_range[memory_ranges].end = end;
						crash_memory_range[memory_ranges].type = RANGE_RAM;
						memory_ranges++;
						start = cend + 1;
						continue;
					}
				}

			} /* end of for loop */
			if (!match) {
				crash_memory_range[memory_ranges].start = start;
				crash_memory_range[memory_ranges].end  = end;
				crash_memory_range[memory_ranges].type = RANGE_RAM;
				memory_ranges++;
			}

			fclose(file);
		}
		closedir(dmem);
	}
	closedir(dir);

	/*
	 * Can not trust the memory regions order that we read from
	 * device-tree. Hence, get the MAX end value.
	 */
	for (i = 0; i < memory_ranges; i++)
		if (saved_max_mem < crash_memory_range[i].end)
			saved_max_mem = crash_memory_range[i].end;

	*range = crash_memory_range;
	*ranges = memory_ranges;
#if DEBUG
	int i;
	printf("CRASH MEMORY RANGES\n");
	for(i = 0; i < *ranges; i++) {
		start = crash_memory_range[i].start;
		end = crash_memory_range[i].end;
		fprintf(stderr, "%016Lx-%016Lx\n", start, end);
	}
#endif
	return 0;
}

/*
 * Used to save various memory regions needed for the captured kernel.
 */

void add_usable_mem_rgns(unsigned long long base, unsigned long long size)
{
	int i;
	unsigned long long end = base + size;
	unsigned long long ustart, uend;

	base = _ALIGN_DOWN(base, PAGE_SIZE);
	end = _ALIGN_UP(end, PAGE_SIZE);

	for (i=0; i < usablemem_rgns.size; i++) {
		ustart = usablemem_rgns.ranges[i].start;
		uend = usablemem_rgns.ranges[i].end;
		if (base < uend && end > ustart) {
			if ((base >= ustart) && (end <= uend))
				return;
			if (base < ustart && end > uend) {
				usablemem_rgns.ranges[i].start = base;
				usablemem_rgns.ranges[i].end = end;
				return;
			} else if (base < ustart) {
				usablemem_rgns.ranges[i].start = base;
				return;
			} else if (end > uend){
				usablemem_rgns.ranges[i].end = end;
				return;
			}
		}
	}
	usablemem_rgns.ranges[usablemem_rgns.size].start = base;
	usablemem_rgns.ranges[usablemem_rgns.size++].end = end;

#ifdef DEBUG
	fprintf(stderr, "usable memory rgns size:%d base:%lx size:%lx\n", usablemem_rgns.size, base, size);
#endif
}

/*
 * Used to exclude various memory regions that do not need elf hdr generation
 */

void add_exclude_rgns(unsigned long long base, unsigned long long size)
{
	int i;
	unsigned long long end = base + size;
	unsigned long long xstart, xend;

	for (i=0; i < exclude_rgns.size; i++) {
		xstart = exclude_rgns.ranges[i].start;
		xend = exclude_rgns.ranges[i].end;
		if (base < xend && end > xstart) {
			if ((base >= xstart) && (end <= xend))
				return;
			if (base < xstart && end > xend) {
				exclude_rgns.ranges[i].start = base;
				exclude_rgns.ranges[i].end = end;
				return;
			} else if (base < xstart) {
				exclude_rgns.ranges[i].start = base;
				exclude_rgns.ranges[i].end = xend;
				return;
			} else if (end > xend){
				exclude_rgns.ranges[i].start = xstart;
				exclude_rgns.ranges[i].end = end;
				return;
			}
		}
	}
	exclude_rgns.ranges[exclude_rgns.size].start = base;
	exclude_rgns.ranges[exclude_rgns.size++].end = end;

#ifdef DEBUG
	fprintf(stderr, "exclude rgns size:%d base:%lx end:%lx size:%lx\n", exclude_rgns.size, base, end, size);
#endif
}

static int sort_regions(mem_rgns_t *rgn)
{
	int i, j;
	unsigned long long tstart, tend;
	for (i = 0; i < rgn->size; i++) {
		for (j = 0; j < rgn->size - i - 1; j++) {
			if (rgn->ranges[j].start > rgn->ranges[j+1].start) {
				tstart = rgn->ranges[j].start;
				tend = rgn->ranges[j].end;
				rgn->ranges[j].start = rgn->ranges[j+1].start;
				rgn->ranges[j].end = rgn->ranges[j+1].end;
				rgn->ranges[j+1].start = tstart;
				rgn->ranges[j+1].end = tend;
			}
		}
	}
	return 0;

}

