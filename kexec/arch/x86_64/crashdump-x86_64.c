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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include "../../kexec.h"
#include "../../kexec-elf.h"
#include "../../kexec-syscall.h"
#include "../../crashdump.h"
#include "kexec-x86_64.h"
#include "crashdump-x86_64.h"
#include <x86/x86-linux.h>

static struct crash_elf_info elf_info =
{
	class: ELFCLASS64,
	data: ELFDATA2LSB,
	machine: EM_X86_64,
	backup_src_start: BACKUP_SRC_START,
	backup_src_end: BACKUP_SRC_END,
	page_offset: PAGE_OFFSET,
};

/* Forward Declaration. */
static int exclude_crash_reserve_region(int *nr_ranges);

#define KERN_VADDR_ALIGN	0x100000	/* 1MB */

/* Read kernel physical load addr from the file returned by proc_iomem()
 * (Kernel Code) and store in kexec_info */
static int get_kernel_paddr(struct kexec_info *info)
{
	uint64_t start;

	if (xen_present()) /* Kernel not entity mapped under Xen */
		return 0;

	if (parse_iomem_single("Kernel code\n", &start, NULL) == 0) {
		info->kern_paddr_start = start;
#ifdef DEBUG
		printf("kernel load physical addr start = 0x%016Lx\n", start);
#endif
		return 0;
	}

	fprintf(stderr, "Cannot determine kernel physical load addr\n");
	return -1;
}

/* Retrieve info regarding virtual address kernel has been compiled for and
 * size of the kernel from /proc/kcore. Current /proc/kcore parsing from
 * from kexec-tools fails because of malformed elf notes. A kernel patch has
 * been submitted. For the folks using older kernels, this function
 * hard codes the values to remain backward compatible. Once things stablize
 * we should get rid of backward compatible code. */

static int get_kernel_vaddr_and_size(struct kexec_info *info)
{
	int result;
	const char kcore[] = "/proc/kcore";
	char *buf;
	struct mem_ehdr ehdr;
	struct mem_phdr *phdr, *end_phdr;
	int align;
	unsigned long size;
	uint32_t elf_flags = 0;

	if (xen_present()) /* Kernel not entity mapped under Xen */
		return 0;

	align = getpagesize();
	size = KCORE_ELF_HEADERS_SIZE;
	buf = slurp_file_len(kcore, size);
	if (!buf) {
		fprintf(stderr, "Cannot read %s: %s\n", kcore, strerror(errno));
		return -1;
	}

	/* Don't perform checks to make sure stated phdrs and shdrs are
	 * actually present in the core file. It is not practical
	 * to read the GB size file into a user space buffer, Given the
	 * fact that we don't use any info from that.
	 */
	elf_flags |= ELF_SKIP_FILESZ_CHECK;
	result = build_elf_core_info(buf, size, &ehdr, elf_flags);
	if (result < 0) {
		fprintf(stderr, "ELF core (kcore) parse failed\n");
		return -1;
	}

	/* Traverse through the Elf headers and find the region where
	 * kernel is mapped. */
	end_phdr = &ehdr.e_phdr[ehdr.e_phnum];
	for(phdr = ehdr.e_phdr; phdr != end_phdr; phdr++) {
		if (phdr->p_type == PT_LOAD) {
			unsigned long saddr = phdr->p_vaddr;
			unsigned long eaddr = phdr->p_vaddr + phdr->p_memsz;
			unsigned long size;

			/* Look for kernel text mapping header. */
			if ((saddr >= __START_KERNEL_map) &&
			    (eaddr <= __START_KERNEL_map + KERNEL_TEXT_SIZE)) {
				saddr = (saddr) & (~(KERN_VADDR_ALIGN - 1));
				info->kern_vaddr_start = saddr;
				size = eaddr - saddr;
				/* Align size to page size boundary. */
				size = (size + align - 1) & (~(align - 1));
				info->kern_size = size;
#ifdef DEBUG
			printf("kernel vaddr = 0x%lx size = 0x%lx\n",
					saddr, size);
#endif
				return 0;
			}
		}
	}
	fprintf(stderr, "Can't find kernel text map area from kcore\n");
	return -1;
}

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
	const char *iomem= proc_iomem();
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
	struct memory_range *mem_range, *memmap_p;

	if (get_kernel_paddr(info))
		return -1;

	if (get_kernel_vaddr_and_size(info))
		return -1;

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
	if (crash_create_elf64_headers(info, &elf_info,
				       crash_memory_range, nr_ranges,
				       &tmp, &sz,
				       ELF_CORE_HEADER_ALIGN) < 0)
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

int is_crashkernel_mem_reserved(void)
{
	uint64_t start, end;

	return parse_iomem_single("Crash kernel\n", &start, &end) == 0 ?
	  (start != end) : 0;
}
