/*
 * kexec: Linux boots Linux
 *
 * Created by: Murali M Chakravarthy (muralim@in.ibm.com)
 * Copyright (C) IBM Corporation, 2005. All rights reserved
 * Heavily borrowed from kexec/arch/i386/crashdump-x86.c
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../../kexec.h"
#include "../../kexec-elf.h"
#include "../../kexec-syscall.h"
#include "../../crashdump.h"
#include "kexec-x86_64.h"
#include "crashdump-x86_64.h"
#include <x86/x86-linux.h>

/* Forward Declaration. */
static int exclude_crash_reserve_region(int *nr_ranges);

/* Stores a sorted list of RAM memory ranges for which to create elf headers.
 * A separate program header is created for backup region */
static struct memory_range crash_memory_range[CRASH_MAX_MEMORY_RANGES];

/* Memory region reserved for storing panic kernel and other data. */
static struct memory_range crash_reserved_mem;

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
	const char iomem[]= "/proc/iomem";
	int memory_ranges = 0;
	char line[MAX_LINE];
	FILE *fp;
	unsigned long long start, end;

	fp = fopen(iomem, "r");
	if (!fp) {
		fprintf(stderr, "Cannot open %s: %s\n",
			iomem, strerror(errno));
		return -1;
	}

	/* First entry is for first 640K region. Different bios report first
	 * 640K in different manner hence hardcoding it */
	crash_memory_range[0].start = 0x00000000;
	crash_memory_range[0].end = 0x0009ffff;
	crash_memory_range[0].type = RANGE_RAM;
	memory_ranges++;

	while(fgets(line, sizeof(line), fp) != 0) {
		char *str;
		int type, consumed, count;
		if (memory_ranges >= CRASH_MAX_MEMORY_RANGES)
			break;
		count = sscanf(line, "%Lx-%Lx : %n",
			&start, &end, &consumed);
		if (count != 2)
			continue;
		str = line + consumed;
#ifdef DEBUG
		printf("%016Lx-%016Lx : %s",
			start, end, str);
#endif
		/* Only Dumping memory of type System RAM. */
		if (memcmp(str, "System RAM\n", 11) == 0) {
			type = RANGE_RAM;
		} else if (memcmp(str, "Crash kernel\n", 13) == 0) {
				/* Reserved memory region. New kernel can
				 * use this region to boot into. */
				crash_reserved_mem.start = start;
				crash_reserved_mem.end = end;
				crash_reserved_mem.type = RANGE_RAM;
				continue;
		} else if (memcmp(str, "ACPI Tables\n", 12) == 0) {
			/*
			 * ACPI Tables area need to be passed to new
			 * kernel with appropriate memmap= option. This
			 * is needed so that x86_64 kernel creates linear
			 * mapping for this region which is required for
			 * initializing acpi tables in second kernel.
			 */
			type = RANGE_ACPI;
		} else if(memcmp(str,"ACPI Non-volatile Storage\n",26) == 0 ) {
			type = RANGE_ACPI_NVS;
		} else {
			continue;
		}

		/* First 640K already registered */
		if (start >= 0x00000000 && end <= 0x0009ffff)
			continue;

		crash_memory_range[memory_ranges].start = start;
		crash_memory_range[memory_ranges].end = end;
		crash_memory_range[memory_ranges].type = type;
		memory_ranges++;

		/* Segregate linearly mapped region. */
		if ((MAXMEM - 1) >= start && (MAXMEM - 1) <= end) {
			crash_memory_range[memory_ranges-1].end = MAXMEM -1;

			/* Add segregated region. */
			crash_memory_range[memory_ranges].start = MAXMEM;
			crash_memory_range[memory_ranges].end = end;
			crash_memory_range[memory_ranges].type = type;
			memory_ranges++;
		}
	}
	fclose(fp);
	if (exclude_crash_reserve_region(&memory_ranges) < 0)
		return -1;
	*range = crash_memory_range;
	*ranges = memory_ranges;
#ifdef DEBUG
	int i;
	printf("CRASH MEMORY RANGES\n");
	for(i = 0; i < memory_ranges; i++) {
		start = crash_memory_range[i].start;
		end = crash_memory_range[i].end;
		printf("%016Lx-%016Lx\n", start, end);
	}
#endif
	return 0;
}

/* Removes crash reserve region from list of memory chunks for whom elf program
 * headers have to be created. Assuming crash reserve region to be a single
 * continuous area fully contained inside one of the memory chunks */
static int exclude_crash_reserve_region(int *nr_ranges)
{
	int i, j, tidx = -1;
	unsigned long long cstart, cend;
	struct memory_range temp_region;

	/* Crash reserved region. */
	cstart = crash_reserved_mem.start;
	cend = crash_reserved_mem.end;

	for (i = 0; i < (*nr_ranges); i++) {
		unsigned long long mstart, mend;
		mstart = crash_memory_range[i].start;
		mend = crash_memory_range[i].end;
		if (cstart < mend && cend > mstart) {
			if (cstart != mstart && cend != mend) {
				/* Split memory region */
				crash_memory_range[i].end = cstart - 1;
				temp_region.start = cend + 1;
				temp_region.end = mend;
				temp_region.type = RANGE_RAM;
				tidx = i+1;
			} else if (cstart != mstart)
				crash_memory_range[i].end = cstart - 1;
			else
				crash_memory_range[i].start = cend + 1;
		}
	}
	/* Insert split memory region, if any. */
	if (tidx >= 0) {
		if (*nr_ranges == CRASH_MAX_MEMORY_RANGES) {
			/* No space to insert another element. */
			fprintf(stderr, "Error: Number of crash memory ranges"
					" excedeed the max limit\n");
			return -1;
		}
		for (j = (*nr_ranges - 1); j >= tidx; j--)
			crash_memory_range[j+1] = crash_memory_range[j];
		crash_memory_range[tidx].start = temp_region.start;
		crash_memory_range[tidx].end = temp_region.end;
		crash_memory_range[tidx].type = temp_region.type;
		(*nr_ranges)++;
	}
	return 0;
}

/* Adds a segment from list of memory regions which new kernel can use to
 * boot. Segment start and end should be aligned to 1K boundary. */
static int add_memmap(struct memory_range *memmap_p, unsigned long long addr,
								size_t size)
{
	int i, j, nr_entries = 0, tidx = 0, align = 1024;
	unsigned long long mstart, mend;

	/* Do alignment check. */
	if ((addr%align) || (size%align))
		return -1;

	/* Make sure at least one entry in list is free. */
	for (i = 0; i < CRASH_MAX_MEMMAP_NR;  i++) {
		mstart = memmap_p[i].start;
		mend = memmap_p[i].end;
		if (!mstart  && !mend)
			break;
		else
			nr_entries++;
	}
	if (nr_entries == CRASH_MAX_MEMMAP_NR)
		return -1;

	for (i = 0; i < CRASH_MAX_MEMMAP_NR;  i++) {
		mstart = memmap_p[i].start;
		mend = memmap_p[i].end;
		if (mstart == 0 && mend == 0)
			break;
		if (mstart <= (addr+size-1) && mend >=addr)
			/* Overlapping region. */
			return -1;
		else if (addr > mend)
			tidx = i+1;
	}
		/* Insert the memory region. */
		for (j = nr_entries-1; j >= tidx; j--)
			memmap_p[j+1] = memmap_p[j];
		memmap_p[tidx].start = addr;
		memmap_p[tidx].end = addr + size - 1;
#ifdef DEBUG
	printf("Memmap after adding segment\n");
	for (i = 0; i < CRASH_MAX_MEMMAP_NR;  i++) {
		mstart = memmap_p[i].start;
		mend = memmap_p[i].end;
		if (mstart == 0 && mend == 0)
			break;
		printf("%016llx - %016llx\n",
			mstart, mend);
	}
#endif
	return 0;
}

/* Removes a segment from list of memory regions which new kernel can use to
 * boot. Segment start and end should be aligned to 1K boundary. */
static int delete_memmap(struct memory_range *memmap_p, unsigned long long addr,
								size_t size)
{
	int i, j, nr_entries = 0, tidx = -1, operation = 0, align = 1024;
	unsigned long long mstart, mend;
	struct memory_range temp_region;

	/* Do alignment check. */
	if ((addr%align) || (size%align))
		return -1;

	/* Make sure at least one entry in list is free. */
	for (i = 0; i < CRASH_MAX_MEMMAP_NR;  i++) {
		mstart = memmap_p[i].start;
		mend = memmap_p[i].end;
		if (!mstart  && !mend)
			break;
		else
			nr_entries++;
	}
	if (nr_entries == CRASH_MAX_MEMMAP_NR)
		/* List if full */
		return -1;

	for (i = 0; i < CRASH_MAX_MEMMAP_NR;  i++) {
		mstart = memmap_p[i].start;
		mend = memmap_p[i].end;
		if (mstart == 0 && mend == 0)
			/* Did not find the segment in the list. */
			return -1;
		if (mstart <= addr && mend >= (addr + size - 1)) {
			if (mstart == addr && mend == (addr + size - 1)) {
				/* Exact match. Delete region */
				operation = -1;
				tidx = i;
				break;
			}
			if (mstart != addr && mend != (addr + size - 1)) {
				/* Split in two */
				memmap_p[i].end = addr - 1;
				temp_region.start = addr + size;
				temp_region.end = mend;
				operation = 1;
				tidx = i;
				break;
			}

			/* No addition/deletion required. Adjust the existing.*/
			if (mstart != addr) {
				memmap_p[i].end = addr - 1;
				break;
			} else {
				memmap_p[i].start = addr + size;
				break;
			}
		}
	}
	if ((operation == 1) && tidx >=0) {
		/* Insert the split memory region. */
		for (j = nr_entries-1; j > tidx; j--)
			memmap_p[j+1] = memmap_p[j];
		memmap_p[tidx+1] = temp_region;
	}
	if ((operation == -1) && tidx >=0) {
		/* Delete the exact match memory region. */
		for (j = i+1; j < CRASH_MAX_MEMMAP_NR; j++)
			memmap_p[j-1] = memmap_p[j];
		memmap_p[j-1].start = memmap_p[j-1].end = 0;
	}
#ifdef DEBUG
	printf("Memmap after deleting segment\n");
	for (i = 0; i < CRASH_MAX_MEMMAP_NR;  i++) {
		mstart = memmap_p[i].start;
		mend = memmap_p[i].end;
		if (mstart == 0 && mend == 0) {
			break;
		}
		printf("%016llx - %016llx\n",
			mstart, mend);
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

/* Adds the appropriate memmap= options to command line, indicating the
 * memory regions the new kernel can use to boot into. */
static int cmdline_add_memmap(char *cmdline, struct memory_range *memmap_p)
{
	int i, cmdlen, len, min_sizek = 100;
	char str_mmap[256], str_tmp[20];

	/* Exact map */
	strcpy(str_mmap, " memmap=exactmap");
	len = strlen(str_mmap);
	cmdlen = strlen(cmdline) + len;
	if (cmdlen > (COMMAND_LINE_SIZE - 1))
		die("Command line overflow\n");
	strcat(cmdline, str_mmap);

	for (i = 0; i < CRASH_MAX_MEMMAP_NR;  i++) {
		unsigned long startk, endk;
		startk = (memmap_p[i].start/1024);
		endk = ((memmap_p[i].end + 1)/1024);
		if (!startk && !endk)
			/* All regions traversed. */
			break;

		/* A region is not worth adding if region size < 100K. It eats
		 * up precious command line length. */
		if ((endk - startk) < min_sizek)
			continue;
		strcpy (str_mmap, " memmap=");
		ultoa((endk-startk), str_tmp);
		strcat (str_mmap, str_tmp);
		strcat (str_mmap, "K@");
		ultoa(startk, str_tmp);
		strcat (str_mmap, str_tmp);
		strcat (str_mmap, "K");
		len = strlen(str_mmap);
		cmdlen = strlen(cmdline) + len;
		if (cmdlen > (COMMAND_LINE_SIZE - 1))
			die("Command line overflow\n");
		strcat(cmdline, str_mmap);
	}
#ifdef DEBUG
		printf("Command line after adding memmap\n");
		printf("%s\n", cmdline);
#endif
	return 0;
}

/* Adds the elfcorehdr= command line parameter to command line. */
static int cmdline_add_elfcorehdr(char *cmdline, unsigned long addr)
{
	int cmdlen, len, align = 1024;
	char str[30], *ptr;

	/* Passing in elfcorehdr=xxxK format. Saves space required in cmdline.
	 * Ensure 1K alignment*/
	if (addr%align)
		return -1;
	addr = addr/align;
	ptr = str;
	strcpy(str, " elfcorehdr=");
	ptr += strlen(str);
	ultoa(addr, ptr);
	strcat(str, "K");
	len = strlen(str);
	cmdlen = strlen(cmdline) + len;
	if (cmdlen > (COMMAND_LINE_SIZE - 1))
		die("Command line overflow\n");
	strcat(cmdline, str);
#ifdef DEBUG
		printf("Command line after adding elfcorehdr\n");
		printf("%s\n", cmdline);
#endif
	return 0;
}

/* Appends memmap=X#Y commandline for ACPI to command line*/
static int cmdline_add_memmap_acpi(char *cmdline, unsigned long start,
					unsigned long end)
{
	int cmdlen, len, align = 1024;
	unsigned long startk, endk;
	char str_mmap[256], str_tmp[20];

	if (!(end - start))
		return 0;

	startk = start/1024;
	endk = (end + align - 1)/1024;
	strcpy (str_mmap, " memmap=");
	ultoa((endk - startk), str_tmp);
	strcat (str_mmap, str_tmp);
	strcat (str_mmap, "K#");
	ultoa(startk, str_tmp);
	strcat (str_mmap, str_tmp);
	strcat (str_mmap, "K");
	len = strlen(str_mmap);
	cmdlen = strlen(cmdline) + len;
	if (cmdlen > (COMMAND_LINE_SIZE - 1))
		die("Command line overflow\n");
	strcat(cmdline, str_mmap);

#ifdef DEBUG
		printf("Command line after adding acpi memmap\n");
		printf("%s\n", cmdline);
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
	uint64_t notes_addr;

	bufp = (char*) buf;

	/* Setup ELF Header*/
	elf = (Elf64_Ehdr *) bufp;
	bufp += sizeof(Elf64_Ehdr);
	memcpy(elf->e_ident, ELFMAG, SELFMAG);
	elf->e_ident[EI_CLASS]  = ELFCLASS64;
	elf->e_ident[EI_DATA]   = ELFDATA2LSB;
	elf->e_ident[EI_VERSION]= EV_CURRENT;
	elf->e_ident[EI_OSABI] = ELFOSABI_NONE;
	memset(elf->e_ident+EI_PAD, 0, EI_NIDENT-EI_PAD);
	elf->e_type	= ET_CORE;
	elf->e_machine	= EM_X86_64;
	elf->e_version	= EV_CURRENT;
	elf->e_entry	= 0;
	elf->e_phoff	= sizeof(Elf64_Ehdr);
	elf->e_shoff	= 0;
	elf->e_flags	= 0;
	elf->e_ehsize   = sizeof(Elf64_Ehdr);
	elf->e_phentsize= sizeof(Elf64_Phdr);
	elf->e_phnum    = 0;
	elf->e_shentsize= 0;
	elf->e_shnum    = 0;
	elf->e_shstrndx = 0;

	/* PT_NOTE program headers. One per cpu*/
	nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
	if (nr_cpus < 0) {
		return -1;
	}

	/* Need to find a better way to determine per cpu notes section size. */
#define MAX_NOTE_BYTES	1024
	for (i = 0; i < nr_cpus; i++) {
		if (get_crash_notes_per_cpu(i, &notes_addr) < 0) {
			/* This cpu is not present. Skip it. */
			continue;
		}

		phdr = (Elf64_Phdr *) bufp;
		bufp += sizeof(Elf64_Phdr);
		phdr->p_type	= PT_NOTE;
		phdr->p_flags	= 0;
		phdr->p_offset  = phdr->p_paddr = notes_addr;
		phdr->p_vaddr   = 0;
		phdr->p_filesz	= phdr->p_memsz	= MAX_NOTE_BYTES;
		/* Do we need any alignment of segments? */
		phdr->p_align	= 0;

		/* Increment number of program headers. */
		(elf->e_phnum)++;
	}

	/* Setup PT_LOAD type program header for every system RAM chunk.
	 * A seprate program header for Backup Region*/
	for (i = 0; i < CRASH_MAX_MEMORY_RANGES; i++) {
		unsigned long long mstart, mend;
		mstart = crash_memory_range[i].start;
		mend = crash_memory_range[i].end;
		if (!mstart && !mend)
			break;
		if (crash_memory_range[i].type != RANGE_RAM)
			break;
		phdr = (Elf64_Phdr *) bufp;
		bufp += sizeof(Elf64_Phdr);
		phdr->p_type	= PT_LOAD;
		phdr->p_flags	= PF_R|PF_W|PF_X;
		if (mstart == BACKUP_SRC_START && mend == BACKUP_SRC_END)
			phdr->p_offset	= info->backup_start;
		else
			phdr->p_offset	= mstart;

		/* Handle linearly mapped region.*/

		/* Filling the vaddr conditionally as we have two linearly
		 * mapped regions here. One is __START_KERNEL_map 0 to 40 MB
		 * other one is PAGE_OFFSET */

		if ((mend <= (MAXMEM - 1)) && mstart < KERNEL_TEXT_SIZE)
			phdr->p_vaddr = mstart + __START_KERNEL_map;
		else {
			if (mend <= (MAXMEM - 1))
				phdr->p_vaddr = mstart + PAGE_OFFSET;
			else
				phdr->p_vaddr = -1ULL;
		}
		phdr->p_paddr = mstart;
		phdr->p_filesz	= phdr->p_memsz	= mend - mstart + 1;
		/* Do we need any alignment of segments? */
		phdr->p_align	= 0;

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
	int nr_ranges, align = 1024, i;
	long int nr_cpus = 0;
	struct memory_range *mem_range, *memmap_p;

	if (get_crash_memory_ranges(&mem_range, &nr_ranges) < 0)
		return -1;

	/* Memory regions which panic kernel can safely use to boot into */
	sz = (sizeof(struct memory_range) * (KEXEC_MAX_SEGMENTS + 1));
	memmap_p = xmalloc(sz);
	memset(memmap_p, 0, sz);
	add_memmap(memmap_p, BACKUP_SRC_START, BACKUP_SRC_SIZE);
	sz = crash_reserved_mem.end - crash_reserved_mem.start +1;
	add_memmap(memmap_p, crash_reserved_mem.start, sz);

	/* Create a backup region segment to store backup data*/
	sz = (BACKUP_SRC_SIZE + align - 1) & ~(align - 1);
	tmp = xmalloc(sz);
	memset(tmp, 0, sz);
	info->backup_start = add_buffer(info, tmp, sz, sz, align,
				0, max_addr, 1);
	if (delete_memmap(memmap_p, info->backup_start, sz) < 0)
		return -1;

	/* Create elf header segment and store crash image data. */
	nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
	if (nr_cpus < 0) {
		fprintf(stderr,"kexec_load (elf header segment)"
			" failed: %s\n", strerror(errno));
		return -1;
	}
	sz = 	sizeof(Elf64_Ehdr) + nr_cpus * sizeof(Elf64_Phdr) +
			nr_ranges * sizeof(Elf64_Phdr);
	sz = (sz + align - 1) & ~(align -1);
	tmp = xmalloc(sz);
	memset(tmp, 0, sz);

	/* Prepare ELF64 core heaers. */
	if (prepare_crash_memory_elf64_headers(info, tmp, sz) < 0)
		return -1;

	/* Hack: With some ld versions (GNU ld version 2.14.90.0.4 20030523),
	 * vmlinux program headers show a gap of two pages between bss segment
	 * and data segment but effectively kernel considers it as bss segment
	 * and overwrites the any data placed there. Hence bloat the memsz of
	 * elf core header segment to 16K to avoid being placed in such gaps.
	 * This is a makeshift solution until it is fixed in kernel.
	 */
	elfcorehdr = add_buffer(info, tmp, sz, 16*1024, align, min_base,
							max_addr, -1);
	if (delete_memmap(memmap_p, elfcorehdr, sz) < 0)
		return -1;
	cmdline_add_memmap(mod_cmdline, memmap_p);
	cmdline_add_elfcorehdr(mod_cmdline, elfcorehdr);

	/* Inform second kernel about the presence of ACPI tables. */
	for (i = 0; i < CRASH_MAX_MEMORY_RANGES; i++) {
		unsigned long start, end;
		if ( !( mem_range[i].type == RANGE_ACPI
			|| mem_range[i].type == RANGE_ACPI_NVS) )
			continue;
		start = mem_range[i].start;
		end = mem_range[i].end;
		cmdline_add_memmap_acpi(mod_cmdline, start, end);
	}
	return 0;
}
