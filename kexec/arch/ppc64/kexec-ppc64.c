/*
 * kexec: Linux boots Linux
 *
 * Copyright (C) 2003-2005  Eric Biederman (ebiederm@xmission.com)
 * Copyright (C) 2005  R Sharada (sharada@in.ibm.com), IBM Corporation
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
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <getopt.h>
#include <sys/utsname.h>
#include "../../kexec.h"
#include "../../kexec-syscall.h"
#include "kexec-ppc64.h"
#include "crashdump-ppc64.h"
#include <arch/options.h>

static struct exclude_range *exclude_range = NULL;
static struct memory_range *memory_range = NULL;
static struct memory_range *base_memory_range = NULL;
static unsigned long long rmo_top;
unsigned long long memory_max = 0;
static int nr_memory_ranges, nr_exclude_ranges;
unsigned long long crash_base, crash_size;
unsigned int rtas_base, rtas_size;
int max_memory_ranges;

static int sort_base_ranges();


static void cleanup_memory_ranges()
{
	if (memory_range)
		free(memory_range);
	if (base_memory_range)
		free(base_memory_range);
	if (exclude_range)
		free(exclude_range);
	if (usablemem_rgns.ranges)
		free(usablemem_rgns.ranges);
}

/*
 * Allocate memory for various data structures used to hold
 * values of different memory ranges
 */
static int alloc_memory_ranges()
{
	int memory_range_len, exclude_range_len;

	memory_range_len = sizeof(struct memory_range) * max_memory_ranges;
	exclude_range_len = sizeof(struct exclude_range) * max_memory_ranges;

	memory_range = (struct memory_range *) malloc(memory_range_len);
	if (!memory_range)
		return -1;

	base_memory_range = (struct memory_range *) malloc(memory_range_len);
	if (!base_memory_range)
		goto err1;

	exclude_range = (struct exclude_range *) malloc(exclude_range_len);
	if (!exclude_range)
		goto err1;

	usablemem_rgns.ranges = (struct exclude_range *)
				malloc(exclude_range_len);
	if (!(usablemem_rgns.ranges))
		goto err1;

	memset(memory_range, 0, memory_range_len);
	memset(base_memory_range, 0, memory_range_len);
	memset(exclude_range, 0, exclude_range_len);
	memset(usablemem_rgns.ranges, 0, exclude_range_len);
	return 0;

err1:
	fprintf(stderr, "memory range structure allocation failure\n");
	cleanup_memory_ranges();
	return -1;

}

/*
 * Count the memory@ nodes under /proc/device-tree and populate the
 * max_memory_ranges variable. This variable replaces MAX_MEMORY_RANGES
 * macro used earlier.
 */
static int count_memory_ranges()
{
	char device_tree[256] = "/proc/device-tree/";
	struct dirent *dentry;
	DIR *dir;

	if ((dir = opendir(device_tree)) == NULL) {
		perror(device_tree);
		return -1;
	}

	while ((dentry = readdir(dir)) != NULL) {
		if (strncmp(dentry->d_name, "memory@", 7))
			continue;
		max_memory_ranges++;
	}
	closedir(dir);

	return 0;
}

/* Get base memory ranges */
static int get_base_ranges()
{
	int local_memory_ranges = 0;
	char device_tree[256] = "/proc/device-tree/";
	char fname[256];
	char buf[MAXBYTES-1];
	DIR *dir, *dmem;
	FILE *file;
	struct dirent *dentry, *mentry;
	int n;

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
			if (local_memory_ranges >= max_memory_ranges) {
				fclose(file);
				break;
			}
			base_memory_range[local_memory_ranges].start =
				((unsigned long long *)buf)[0];
			base_memory_range[local_memory_ranges].end  =
				base_memory_range[local_memory_ranges].start +
				((unsigned long long *)buf)[1];
			base_memory_range[local_memory_ranges].type = RANGE_RAM;
			local_memory_ranges++;
			dfprintf(stderr, "%016llx-%016llx : %x\n",
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

/* Sort the base ranges in memory - this is useful for ensuring that our
 * ranges are in ascending order, even if device-tree read of memory nodes
 * is done differently. Also, could be used for other range coalescing later
 */
static int sort_base_ranges()
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

/* Sort the exclude ranges in memory */
static int sort_ranges()
{
	int i, j;
	unsigned long long tstart, tend;
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

/* Get devtree details and create exclude_range array
 * Also create usablemem_ranges for KEXEC_ON_CRASH
 */
static int get_devtree_details(unsigned long kexec_flags)
{
	unsigned long long rmo_base;
	unsigned long long tce_base;
	unsigned int tce_size;
	unsigned long long htab_base, htab_size;
	unsigned long long kernel_end;
	char buf[MAXBYTES-1];
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
			strncmp(dentry->d_name, "memory@0", 8) &&
			strncmp(dentry->d_name, "pci@", 4) &&
			strncmp(dentry->d_name, "rtas", 4))
			continue;
		strcpy(fname, device_tree);
		strcat(fname, dentry->d_name);
		if ((cdir = opendir(fname)) == NULL) {
			perror(fname);
			closedir(dir);
			return -1;
		}

		if (strncmp(dentry->d_name, "chosen", 6) == 0) {
			strcat(fname, "/linux,kernel-end");
			if ((file = fopen(fname, "r")) == NULL) {
				perror(fname);
				closedir(cdir);
				closedir(dir);
				return -1;
			}
			if (fread(&kernel_end, sizeof(unsigned long), 1, file) != 1) {
				perror(fname);
				fclose(file);
				closedir(cdir);
				closedir(dir);
				return -1;
			}
			fclose(file);

			/* Add kernel memory to exclude_range */
			exclude_range[i].start = 0x0UL;
			exclude_range[i].end = kernel_end;
			i++;

			if (kexec_flags & KEXEC_ON_CRASH) {
				memset(fname, 0, sizeof(fname));
				strcpy(fname, device_tree);
				strcat(fname, dentry->d_name);
				strcat(fname, "/linux,crashkernel-base");
				if ((file = fopen(fname, "r")) == NULL) {
					perror(fname);
					closedir(cdir);
					closedir(dir);
					return -1;
				}
				if (fread(&crash_base, sizeof(unsigned long), 1,
						file) != 1) {
					perror(fname);
					fclose(file);
					closedir(cdir);
					closedir(dir);
					return -1;
				}
				fclose(file);

				memset(fname, 0, sizeof(fname));
				strcpy(fname, device_tree);
				strcat(fname, dentry->d_name);
				strcat(fname, "/linux,crashkernel-size");
				if ((file = fopen(fname, "r")) == NULL) {
					perror(fname);
					closedir(cdir);
					closedir(dir);
					return -1;
				}
				if (fread(&crash_size, sizeof(unsigned long), 1,
						file) != 1) {
					perror(fname);
					fclose(file);
					closedir(cdir);
					closedir(dir);
					return -1;
				}

				if (crash_base > mem_min)
					mem_min = crash_base;
				if (crash_base + crash_size < mem_max)
					mem_max = crash_base + crash_size;

				add_usable_mem_rgns(0, crash_base + crash_size);
				reserve(KDUMP_BACKUP_LIMIT, crash_base-KDUMP_BACKUP_LIMIT);
			}

			memset(fname, 0, sizeof(fname));
			strcpy(fname, device_tree);
			strcat(fname, dentry->d_name);
			strcat(fname, "/linux,htab-base");
			if ((file = fopen(fname, "r")) == NULL) {
				closedir(cdir);
				if (errno == ENOENT) {
					/* Non LPAR */
					errno = 0;
					continue;
                                }
				perror(fname);
				closedir(dir);
				return -1;
			}
			if (fread(&htab_base, sizeof(unsigned long), 1, file) != 1) {
				perror(fname);
				fclose(file);
				closedir(cdir);
				closedir(dir);
				return -1;
			}
			memset(fname, 0, sizeof(fname));
			strcpy(fname, device_tree);
			strcat(fname, dentry->d_name);
			strcat(fname, "/linux,htab-size");
			if ((file = fopen(fname, "r")) == NULL) {
				perror(fname);
				closedir(cdir);
				closedir(dir);
				return -1;
			}
			if (fread(&htab_size, sizeof(unsigned long), 1, file) != 1) {
				perror(fname);
				fclose(file);
				closedir(cdir);
				closedir(dir);
				return -1;
			}
			/* Add htab address to exclude_range - NON-LPAR only */
			exclude_range[i].start = htab_base;
			exclude_range[i].end = htab_base + htab_size;
			i++;
		} /* chosen */

		if (strncmp(dentry->d_name, "rtas", 4) == 0) {
			strcat(fname, "/linux,rtas-base");
			if ((file = fopen(fname, "r")) == NULL) {
				perror(fname);
				closedir(cdir);
				closedir(dir);
				return -1;
			}
			if (fread(&rtas_base, sizeof(unsigned int), 1, file) != 1) {
				perror(fname);
				fclose(file);
				closedir(cdir);
				closedir(dir);
				return -1;
			}
			memset(fname, 0, sizeof(fname));
			strcpy(fname, device_tree);
			strcat(fname, dentry->d_name);
			strcat(fname, "/rtas-size");
			if ((file = fopen(fname, "r")) == NULL) {
				perror(fname);
				closedir(cdir);
				closedir(dir);
				return -1;
			}
			if (fread(&rtas_size, sizeof(unsigned int), 1, file) != 1) {
				perror(fname);
				fclose(file);
				closedir(cdir);
				closedir(dir);
				return -1;
			}
			closedir(cdir);
			/* Add rtas to exclude_range */
			exclude_range[i].start = rtas_base;
			exclude_range[i].end = rtas_base + rtas_size;
			i++;
			if (kexec_flags & KEXEC_ON_CRASH)
				add_usable_mem_rgns(rtas_base, rtas_size);
		} /* rtas */

		if (strncmp(dentry->d_name, "memory@0", 8) == 0) {
			strcat(fname, "/reg");
			if ((file = fopen(fname, "r")) == NULL) {
				perror(fname);
				closedir(cdir);
				closedir(dir);
				return -1;
			}
			if ((n = fread(buf, 1, MAXBYTES, file)) < 0) {
				perror(fname);
				fclose(file);
				closedir(cdir);
				closedir(dir);
				return -1;
			}
			rmo_base = ((unsigned long long *)buf)[0];
			rmo_top = rmo_base + ((unsigned long long *)buf)[1];
			if (rmo_top > 0x30000000UL)
				rmo_top = 0x30000000UL;

			fclose(file);
			closedir(cdir);
		} /* memory */

		if (strncmp(dentry->d_name, "pci@", 4) == 0) {
			strcat(fname, "/linux,tce-base");
			if ((file = fopen(fname, "r")) == NULL) {
				closedir(cdir);
				if (errno == ENOENT) {
					/* Non LPAR */
					errno = 0;
					continue;
				}
				perror(fname);
				closedir(dir);
				return -1;
			}
			if (fread(&tce_base, sizeof(unsigned long), 1, file) != 1) {
				perror(fname);
				fclose(file);
				closedir(cdir);
				closedir(dir);
				return -1;
			}
			memset(fname, 0, sizeof(fname));
			strcpy(fname, device_tree);
			strcat(fname, dentry->d_name);
			strcat(fname, "/linux,tce-size");
			if ((file = fopen(fname, "r")) == NULL) {
				perror(fname);
				closedir(cdir);
				closedir(dir);
				return -1;
			}
			if (fread(&tce_size, sizeof(unsigned int), 1, file) != 1) {
				perror(fname);
				fclose(file);
				closedir(cdir);
				closedir(dir);
				return -1;
			}
			/* Add tce to exclude_range - NON-LPAR only */
			exclude_range[i].start = tce_base;
			exclude_range[i].end = tce_base + tce_size;
			i++;
			if (kexec_flags & KEXEC_ON_CRASH)
				add_usable_mem_rgns(tce_base, tce_size);
			closedir(cdir);
		} /* pci */
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
}

/* Setup a sorted list of memory ranges. */
int setup_memory_ranges(unsigned long kexec_flags)
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
int get_memory_ranges(struct memory_range **range, int *ranges,
			unsigned long kexec_flags)
{
	if (count_memory_ranges())
		return -1;
	if (alloc_memory_ranges())
		return -1;

	setup_memory_ranges(kexec_flags);
	*range = memory_range;
	*ranges = nr_memory_ranges;
	fprintf(stderr, "get memory ranges:%d\n", nr_memory_ranges);
	return 0;
}

struct file_type file_type[] = {
	{ "elf-ppc64", elf_ppc64_probe, elf_ppc64_load, elf_ppc64_usage },
};
int file_types = sizeof(file_type) / sizeof(file_type[0]);

void arch_usage(void)
{
	fprintf(stderr, "     --command-line=<Command line> command line to append.\n");
	fprintf(stderr, "     --append=<Command line> same as --command-line.\n");
	fprintf(stderr, "     --ramdisk=<filename> Initial RAM disk.\n");
	fprintf(stderr, "     --initrd=<filename> same as --ramdisk.\n");
	fprintf(stderr, "     --devicetreeblob=<filename> Specify device tree blob file.\n");
	fprintf(stderr, "     --elf64-core-headers Prepare core headers in ELF64 format\n");
}

struct arch_options_t arch_options = {
	.core_header_type = CORE_TYPE_ELF64,
};

int arch_process_options(int argc, char **argv)
{
	static const struct option options[] = {
		KEXEC_ARCH_OPTIONS
		{ 0, 0, NULL, 0 },
	};
	static const char short_options[] = KEXEC_ARCH_OPT_STR;
	int opt;

	opterr = 0; /* Don't complain about unrecognized options here */
	while((opt = getopt_long(argc, argv, short_options, options, 0)) != -1) {
		switch(opt) {
		default:
			break;
		case OPT_ELF64_CORE:
			arch_options.core_header_type = CORE_TYPE_ELF64;
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
	if (strcmp(utsname.machine, "ppc64") == 0)
	{
		/* We are running a 32-bit kexec-tools on 64-bit ppc64.
		 * So pass KEXEC_ARCH_PPC64 here
		 */
		info->kexec_flags |= KEXEC_ARCH_PPC64;
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
