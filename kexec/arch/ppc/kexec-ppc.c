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
#include <sys/types.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../kexec.h"
#include "../../kexec-syscall.h"
#include "kexec-ppc.h"
#include <arch/options.h>

#include "config.h"

#ifdef WITH_GAMECUBE
#define MAX_MEMORY_RANGES  64
static struct memory_range memory_range[MAX_MEMORY_RANGES];

static int get_memory_ranges_gc(struct memory_range **range, int *ranges,
					unsigned long UNUSED(kexec_flags))
{
	int memory_ranges = 0;

	/* RAM - lowmem used by DOLs - framebuffer */
	memory_range[memory_ranges].start = 0x00003000;
	memory_range[memory_ranges].end = 0x0174bfff;
	memory_range[memory_ranges].type = RANGE_RAM;
	memory_ranges++;
	*range = memory_range;
	*ranges = memory_ranges;
	return 0;
}
#else
static int use_new_dtb;
static int max_memory_ranges;
static int nr_memory_ranges, nr_exclude_ranges;
static struct memory_range *exclude_range;
static struct memory_range *memory_range;
static struct memory_range *base_memory_range;
static uint64_t memory_max;
uint64_t rmo_top;
unsigned int rtas_base, rtas_size;

/*
 * Count the memory nodes under /proc/device-tree and populate the
 * max_memory_ranges variable. This variable replaces MAX_MEMORY_RANGES
 * macro used earlier.
 */
static int count_memory_ranges(void)
{
	char device_tree[256] = "/proc/device-tree/";
	struct dirent *dentry;
	DIR *dir;

	if ((dir = opendir(device_tree)) == NULL) {
		perror(device_tree);
		return -1;
	}

	while ((dentry = readdir(dir)) != NULL) {
		if (strncmp(dentry->d_name, "memory@", 7) &&
				strcmp(dentry->d_name, "memory"))
			continue;
		max_memory_ranges++;
	}

	/* need to add extra region for retained initrd */
	if (use_new_dtb) {
		max_memory_ranges++;
	}

	closedir(dir);
	return 0;

}

 static void cleanup_memory_ranges(void)
 {
	 free(memory_range);
	 free(base_memory_range);
	 free(exclude_range);
 }

/*
 * Allocate memory for various data structures used to hold
 * values of different memory ranges
 */
static int alloc_memory_ranges(void)
{
	int memory_range_len;

	memory_range_len = sizeof(struct memory_range) * max_memory_ranges;

	memory_range = malloc(memory_range_len);
	if (!memory_range)
		return -1;

	base_memory_range = malloc(memory_range_len);
	if (!base_memory_range)
		goto err1;

	exclude_range = malloc(memory_range_len);
	if (!exclude_range)
		goto err1;

	memset(memory_range, 0, memory_range_len);
	memset(base_memory_range, 0, memory_range_len);
	memset(exclude_range, 0, memory_range_len);
	return 0;

err1:
	fprintf(stderr, "memory range structure allocation failure\n");
	cleanup_memory_ranges();
	return -1;
}

/* Sort the exclude ranges in memory */
static int sort_ranges(void)
{
	int i, j;
	uint64_t tstart, tend;
	for (i = 0; i < nr_exclude_ranges - 1; i++) {
		for (j = 0; j < nr_exclude_ranges - i - 1; j++) {
			if (exclude_range[j].start > exclude_range[j+1].start) {
				tstart = exclude_range[j].start;
				tend = exclude_range[j].end;
				exclude_range[j].start = exclude_range[j+1].start;
				exclude_range[j].end = exclude_range[j+1].end;
				exclude_range[j+1].start = tstart;
				exclude_range[j+1].end = tend;
			}
		}
	}
	return 0;
}

/* Sort the base ranges in memory - this is useful for ensuring that our
 * ranges are in ascending order, even if device-tree read of memory nodes
 * is done differently. Also, could be used for other range coalescing later
 */
static int sort_base_ranges(void)
{
	int i, j;
	unsigned long long tstart, tend;

	for (i = 0; i < nr_memory_ranges - 1; i++) {
		for (j = 0; j < nr_memory_ranges - i - 1; j++) {
			if (base_memory_range[j].start > base_memory_range[j+1].start) {
				tstart = base_memory_range[j].start;
				tend = base_memory_range[j].end;
				base_memory_range[j].start = base_memory_range[j+1].start;
				base_memory_range[j].end = base_memory_range[j+1].end;
				base_memory_range[j+1].start = tstart;
				base_memory_range[j+1].end = tend;
			}
		}
	}
	return 0;
}


#define MAXBYTES 128

/* Get base memory ranges */
static int get_base_ranges(void)
{
	int local_memory_ranges = 0;
	char device_tree[256] = "/proc/device-tree/";
	char fname[256];
	char buf[MAXBYTES];
	DIR *dir, *dmem;
	FILE *file;
	struct dirent *dentry, *mentry;
	int n;

	if ((dir = opendir(device_tree)) == NULL) {
		perror(device_tree);
		return -1;
	}
	while ((dentry = readdir(dir)) != NULL) {
		if (strncmp(dentry->d_name, "memory@", 7) &&
				strcmp(dentry->d_name, "memory"))
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
			if (local_memory_ranges >= max_memory_ranges) {
				fclose(file);
				break;
			}
			base_memory_range[local_memory_ranges].start =
				((uint32_t *)buf)[0];
			base_memory_range[local_memory_ranges].end  =
				base_memory_range[local_memory_ranges].start +
				((uint32_t *)buf)[1];
			base_memory_range[local_memory_ranges].type = RANGE_RAM;
			local_memory_ranges++;
			dbgprintf("%016llx-%016llx : %x\n",
					base_memory_range[local_memory_ranges-1].start,
					base_memory_range[local_memory_ranges-1].end,
					base_memory_range[local_memory_ranges-1].type);
			fclose(file);
		}
		closedir(dmem);
	}
	closedir(dir);
	nr_memory_ranges = local_memory_ranges;
	sort_base_ranges();
	memory_max = base_memory_range[nr_memory_ranges - 1].end;
#ifdef DEBUG
	fprintf(stderr, "get base memory ranges:%d\n", nr_memory_ranges);
#endif
	return 0;
}

/* Get devtree details and create exclude_range array
 * Also create usablemem_ranges for KEXEC_ON_CRASH
 */
static int get_devtree_details(unsigned long kexec_flags)
{
	uint64_t rmo_base;
	char buf[MAXBYTES];
	char device_tree[256] = "/proc/device-tree/";
	char fname[256];
	DIR *dir, *cdir;
	FILE *file;
	struct dirent *dentry;
	int n, i = 0;

	if ((dir = opendir(device_tree)) == NULL) {
		perror(device_tree);
		return -1;
	}

	while ((dentry = readdir(dir)) != NULL) {
		if (strncmp(dentry->d_name, "chosen", 6) &&
				strncmp(dentry->d_name, "memory@", 7) &&
				strcmp(dentry->d_name, "memory") &&
				strncmp(dentry->d_name, "rtas", 4))
			continue;

		strcpy(fname, device_tree);
		strcat(fname, dentry->d_name);
		if ((cdir = opendir(fname)) == NULL) {
			perror(fname);
			goto error_opendir;
		}

		if (strncmp(dentry->d_name, "rtas", 4) == 0) {
			strcat(fname, "/linux,rtas-base");
			if ((file = fopen(fname, "r")) == NULL) {
				perror(fname);
				goto error_opencdir;
			}
			if (fread(&rtas_base, sizeof(unsigned int), 1, file) != 1) {
				perror(fname);
				goto error_openfile;
			}
			memset(fname, 0, sizeof(fname));
			strcpy(fname, device_tree);
			strcat(fname, dentry->d_name);
			strcat(fname, "/rtas-size");
			if ((file = fopen(fname, "r")) == NULL) {
				perror(fname);
				goto error_opencdir;
			}
			if (fread(&rtas_size, sizeof(unsigned int), 1, file) != 1) {
				perror(fname);
				goto error_openfile;
			}
			closedir(cdir);
			/* Add rtas to exclude_range */
			exclude_range[i].start = rtas_base;
			exclude_range[i].end = rtas_base + rtas_size;
			i++;
		} /* rtas */

		if (!strncmp(dentry->d_name, "memory@", 7) ||
				!strcmp(dentry->d_name, "memory")) {
			strcat(fname, "/reg");
			if ((file = fopen(fname, "r")) == NULL) {
				perror(fname);
				goto error_opencdir;
			}
			if ((n = fread(buf, 1, MAXBYTES, file)) < 0) {
				perror(fname);
				goto error_openfile;
			}
			if (n == 8) {
				rmo_base = ((uint32_t *)buf)[0];
				rmo_top = rmo_base + ((uint32_t *)buf)[1];
			} else if (n == 16) {
				rmo_base = ((uint64_t *)buf)[0];
				rmo_top = rmo_base + ((uint64_t *)buf)[1];
			} else {
				fprintf(stderr, "Mem node has invalid size: %d\n", n);
				goto error_openfile;
			}
			if (rmo_top > 0x30000000UL)
				rmo_top = 0x30000000UL;

			fclose(file);
			closedir(cdir);
		} /* memory */
	}
	closedir(dir);

	nr_exclude_ranges = i;

	sort_ranges();

#ifdef DEBUG
	int k;
	for (k = 0; k < i; k++)
		fprintf(stderr, "exclude_range sorted exclude_range[%d] "
				"start:%llx, end:%llx\n", k, exclude_range[k].start,
				exclude_range[k].end);
#endif
	return 0;

error_openfile:
	fclose(file);
error_opencdir:
	closedir(cdir);
error_opendir:
	closedir(dir);
	return -1;
}


/* Setup a sorted list of memory ranges. */
static int setup_memory_ranges(unsigned long kexec_flags)
{
	int i, j = 0;

	/* Get the base list of memory ranges from /proc/device-tree/memory
	 * nodes. Build list of ranges to be excluded from valid memory
	 */

	if (get_base_ranges())
		goto out;
	if (get_devtree_details(kexec_flags))
		goto out;

	for (i = 0; i < nr_exclude_ranges; i++) {
		/* If first exclude range does not start with 0, include the
		 * first hole of valid memory from 0 - exclude_range[0].start
		 */
		if (i == 0) {
			if (exclude_range[i].start != 0) {
				memory_range[j].start = 0;
				memory_range[j].end = exclude_range[i].start - 1;
				memory_range[j].type = RANGE_RAM;
				j++;
			}
		} /* i == 0 */
		/* If the last exclude range does not end at memory_max, include
		 * the last hole of valid memory from exclude_range[last].end -
		 * memory_max
		 */
		if (i == nr_exclude_ranges - 1) {
			if (exclude_range[i].end < memory_max) {
				memory_range[j].start = exclude_range[i].end + 1;
				memory_range[j].end = memory_max;
				memory_range[j].type = RANGE_RAM;
				j++;
				/* Limit the end to rmo_top */
				if (memory_range[j-1].start >= rmo_top) {
					j--;
					break;
				}
				if ((memory_range[j-1].start < rmo_top) &&
						(memory_range[j-1].end >= rmo_top)) {
					memory_range[j-1].end = rmo_top;
					break;
				}
				continue;
			}
		} /* i == nr_exclude_ranges - 1 */
		/* contiguous exclude ranges - skip */
		if (exclude_range[i+1].start == exclude_range[i].end + 1)
			continue;
		memory_range[j].start = exclude_range[i].end + 1;
		memory_range[j].end = exclude_range[i+1].start - 1;
		memory_range[j].type = RANGE_RAM;
		j++;
		/* Limit range to rmo_top */
		if (memory_range[j-1].start >= rmo_top) {
			j--;
			break;
		}
		if ((memory_range[j-1].start < rmo_top) &&
				(memory_range[j-1].end >= rmo_top)) {
			memory_range[j-1].end = rmo_top;
			break;
		}
	}

	/* fixup in case we have no exclude regions */
	if (!j) {
		memory_range[0].start = base_memory_range[0].start;
		memory_range[0].end = rmo_top;
		memory_range[0].type = RANGE_RAM;
		nr_memory_ranges = 1;
	} else
		nr_memory_ranges = j;

#ifdef DEBUG
	int k;
	for (k = 0; k < j; k++)
		fprintf(stderr, "setup_memory_ranges memory_range[%d] "
				"start:%llx, end:%llx\n", k, memory_range[k].start,
				memory_range[k].end);
#endif
	return 0;

out:
	cleanup_memory_ranges();
	return -1;
}


/* Return a list of valid memory ranges */
int get_memory_ranges_dt(struct memory_range **range, int *ranges,
		unsigned long kexec_flags)
{
	if (count_memory_ranges())
		return -1;
	if (alloc_memory_ranges())
		return -1;
	if (setup_memory_ranges(kexec_flags))
		return -1;

	*range = memory_range;
	*ranges = nr_memory_ranges;
	return 0;
}
#endif

/* Return a sorted list of memory ranges. */
int get_memory_ranges(struct memory_range **range, int *ranges,
					unsigned long kexec_flags)
{
#ifdef WITH_GAMECUBE
	return get_memory_ranges_gc(range, ranges, kexec_flags);
#else
	return get_memory_ranges_dt(range, ranges, kexec_flags);
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
