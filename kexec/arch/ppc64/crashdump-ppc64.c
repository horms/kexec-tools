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

extern struct arch_options_t arch_options;

/* Stores a sorted list of RAM memory ranges for which to create elf headers.
 * A separate program header is created for backup region
 */
static struct memory_range crash_memory_range[CRASH_MAX_MEMORY_RANGES];

/*
 * Used to save various memory ranges/regions needed for the captured
 * kernel to boot. (lime memmap= option in other archs)
 */
mem_rgns_t usablemem_rgns = {0, };

/*
 * To store the memory size of the first kernel and this value will be
 * passed to the second kernel as command line (savemaxmem=xM).
 * The second kernel will be calculated saved_max_pfn based on this
 * variable.
 * Since we are creating/using usable-memory property, there is no way
 * we can determine the RAM size unless parsing the device-tree/memoy@/reg
 * property in the kernel.
 */
unsigned long saved_max_mem = 0;

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
	int i, n;
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
			if (memory_ranges >= MAX_MEMORY_RANGES) {
				/* No space to insert another element. */
				fprintf(stderr,
					"Error: Number of crash memory ranges"
					" excedeed the max limit\n");
				return -1;
			}

			start = ((unsigned long long *)buf)[0];
			end = start + ((unsigned long long *)buf)[1];
			if (start == 0 && end >= 0x8000)
				start = 0x8000;

			cstart = crash_base;
			cend = crash_base + crash_size;
			/*
			 * Exclude the region that lies within crashkernel
			 */
			if (cstart < end && cend > start) {
				if (start < cstart && end > cend) {
					crash_memory_range[memory_ranges].start = start;
					crash_memory_range[memory_ranges].end = cstart;
					crash_memory_range[memory_ranges].type = RANGE_RAM;
					memory_ranges++;
					crash_memory_range[memory_ranges].start = cend;
					crash_memory_range[memory_ranges].end = end;
					crash_memory_range[memory_ranges].type = RANGE_RAM;
					memory_ranges++;
				} else if (start < cstart) {
					crash_memory_range[memory_ranges].start = start;
					crash_memory_range[memory_ranges].end = cstart;
					crash_memory_range[memory_ranges].type = RANGE_RAM;
					memory_ranges++;
				} else if (end > cend){
					crash_memory_range[memory_ranges].start = cend;
					crash_memory_range[memory_ranges].end = end;
					crash_memory_range[memory_ranges].type = RANGE_RAM;
					memory_ranges++;
				}
			} else {
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
	 * If RTAS region is overlapped with crashkernel, need to create ELF
	 * Program header for the overlapped memory.
	 */
	if (crash_base < rtas_base + rtas_size &&
		rtas_base < crash_base + crash_size) {
		cstart = rtas_base;
		cend = rtas_base + rtas_size;
		if (cstart < crash_base)
			cstart = crash_base;
		if (cend > crash_base + crash_size)
			cend = crash_base + crash_size;
		crash_memory_range[memory_ranges].start = cstart;
		crash_memory_range[memory_ranges++].end = cend;
	}
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

/* Converts unsigned long to ascii string. */
static void ultoa(unsigned long i, char *str)
{
	int j = 0, k;
	char tmp;

	do {
		str[j++] = i % 10 + '0';
	} while ((i /=10) > 0);
	str[j] = '\0';

	/* Reverse the string. */
	for (j = 0, k = strlen(str) - 1; j < k; j++, k--) {
		tmp = str[k];
		str[k] = str[j];
		str[j] = tmp;
	}
}

static int add_cmdline_param(char *cmdline, unsigned long addr,
				char *cmdstr, char *byte)
{
	int cmdlen, len, align = 1024;
	char str[COMMAND_LINE_SIZE], *ptr;

	/* Passing in =xxxK / =xxxM format. Saves space required in cmdline.*/
	switch (byte[0]) {
		case 'K':
			if (addr%align)
				return -1;
			addr = addr/align;
			break;
		case 'M':
			addr = addr/(align *align);
			break;
	}
	ptr = str;
	strcpy(str, cmdstr);
	ptr += strlen(str);
	ultoa(addr, ptr);
	strcat(str, byte);
	len = strlen(str);
	cmdlen = strlen(cmdline) + len;
	if (cmdlen > (COMMAND_LINE_SIZE - 1))
		die("Command line overflow\n");
	strcat(cmdline, str);
#if DEBUG
	fprintf(stderr, "Command line after adding elfcorehdr: %s\n", cmdline);
#endif
	return 0;
}

/* Prepares the crash memory elf64 headers and stores in supplied buffer. */
static int prepare_crash_memory_elf64_headers(struct kexec_info *info,
						void *buf, unsigned long size)
{
	Elf64_Ehdr *elf;
	Elf64_Phdr *phdr;
	int i;
	char *bufp;
	long int nr_cpus = 0;
	unsigned long notes_addr;

	bufp = (char*) buf;

	/* Setup ELF Header*/
	elf = (Elf64_Ehdr *) bufp;
	bufp += sizeof(Elf64_Ehdr);
	memcpy(elf->e_ident, ELFMAG, SELFMAG);
	elf->e_ident[EI_CLASS]  = ELFCLASS64;
	elf->e_ident[EI_DATA]   = ELFDATA2MSB;
	elf->e_ident[EI_VERSION]= EV_CURRENT;
	elf->e_ident[EI_OSABI] = ELFOSABI_NONE;
	memset(elf->e_ident+EI_PAD, 0, EI_NIDENT-EI_PAD);
	elf->e_type     = ET_CORE;
	elf->e_machine  = EM_PPC64;
	elf->e_version  = EV_CURRENT;
	elf->e_entry    = 0;
	elf->e_phoff    = sizeof(Elf64_Ehdr);
	elf->e_shoff    = 0;
	elf->e_flags    = 0;
	elf->e_ehsize   = sizeof(Elf64_Ehdr);
	elf->e_phentsize= sizeof(Elf64_Phdr);
	elf->e_phnum    = 0;
	elf->e_shentsize= 0;
	elf->e_shnum    = 0;
	elf->e_shstrndx = 0;

	/* PT_NOTE program headers. One per cpu*/
	nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
	if (nr_cpus < 0)
		return -1;

	/* Need to find a better way to determine per cpu notes section size. */
#define MAX_NOTE_BYTES  1024
	for (i = 0; i < nr_cpus; i++) {
		if (get_crash_notes_per_cpu(i, &notes_addr) < 0) {
			/* This cpu is not present. Skip it. */
			continue;
		}
		phdr = (Elf64_Phdr *) bufp;
		bufp += sizeof(Elf64_Phdr);
		phdr->p_type    = PT_NOTE;
		phdr->p_flags   = 0;
		phdr->p_offset  = phdr->p_paddr =  notes_addr;
		phdr->p_vaddr   = 0;
		phdr->p_filesz  = phdr->p_memsz = MAX_NOTE_BYTES;
		/* Do we need any alignment of segments? */
		phdr->p_align   = 0;

		/* Increment number of program headers. */
		(elf->e_phnum)++;
	}

	/* Setup PT_LOAD type program header for every system RAM chunk.
	 * A seprate program header for Backup Region
	 */
	for (i = 0; i < CRASH_MAX_MEMORY_RANGES; i++) {
		unsigned long long mstart, mend;
		mstart = crash_memory_range[i].start;
		mend = crash_memory_range[i].end;
		if (!mstart && !mend)
			break;
		phdr = (Elf64_Phdr *) bufp;
		bufp += sizeof(Elf64_Phdr);
		phdr->p_type    = PT_LOAD;
		phdr->p_flags   = PF_R|PF_W|PF_X;
		if (mstart == BACKUP_SRC_START && mend == BACKUP_SRC_END)
			phdr->p_offset  = info->backup_start;
		else
			phdr->p_offset  = mstart;
		/* Handle linearly mapped region.*/
		if (mend <= (MAXMEM - 1))
			phdr->p_vaddr = mstart + PAGE_OFFSET;
		else
			phdr->p_vaddr = -1ULL;
		phdr->p_paddr = mstart;
		phdr->p_filesz  = phdr->p_memsz = mend - mstart;
		/* Do we need any alignment of segments? */
		phdr->p_align   = 0;

		/* Increment number of program headers. */
		(elf->e_phnum)++;
	}
	return 0;
}

/* Loads additional segments in case of a panic kernel is being loaded.
 * One segment for backup region, another segment for storing elf headers
 * for crash memory image.
 */
int load_crashdump_segments(struct kexec_info *info, char* mod_cmdline,
				unsigned long max_addr, unsigned long min_base)
{
	void *tmp;
	unsigned long sz, elfcorehdr;
	int nr_ranges, align = 1024;
	long int nr_cpus = 0;
	struct memory_range *mem_range;

	if (get_crash_memory_ranges(&mem_range, &nr_ranges) < 0)
		return -1;

	/* Create a backup region segment to store backup data*/
	sz = (BACKUP_SRC_SIZE + align - 1) & ~(align - 1);
	tmp = xmalloc(sz);
	memset(tmp, 0, sz);
	info->backup_start = add_buffer(info, tmp, sz, sz, align,
					0, max_addr, 1);
	reserve(info->backup_start, sz);
	/* Create elf header segment and store crash image data. */
	nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
	if (nr_cpus < 0) {
		fprintf(stderr,"kexec_load (elf header segment)"
			" failed: %s\n", strerror(errno));
		return -1;
	}
	if (arch_options.core_header_type == CORE_TYPE_ELF64) {
		sz =    sizeof(Elf64_Ehdr) +
			nr_cpus * sizeof(Elf64_Phdr) +
			nr_ranges * sizeof(Elf64_Phdr);
	} else {
		sz =    sizeof(Elf32_Ehdr) +
			nr_cpus * sizeof(Elf32_Phdr) +
			nr_ranges * sizeof(Elf32_Phdr);
	}
	sz = (sz + align - 1) & ~(align -1);
	tmp = xmalloc(sz);
	memset(tmp, 0, sz);
	if (arch_options.core_header_type == CORE_TYPE_ELF64) {
		if (prepare_crash_memory_elf64_headers(info, tmp, sz) < 0)
			return -1;
	}

	elfcorehdr = add_buffer(info, tmp, sz, sz, align, min_base,
				max_addr, 1);
	reserve(elfcorehdr, sz);
	/* modify and store the cmdline in a global array. This is later
	 * read by flatten_device_tree and modified if required
	 */
	add_cmdline_param(mod_cmdline, elfcorehdr, " elfcorehdr=", "K");
	add_cmdline_param(mod_cmdline, saved_max_mem, " savemaxmem=", "M");
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

#if 0
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
#endif

