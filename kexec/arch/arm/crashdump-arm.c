/*
 * kexec: Linux boots Linux
 *
 * Copyright (C) Nokia Corporation, 2010.
 * Author: Mika Westerberg
 *
 * Based on x86 implementation
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
#include <limits.h>
#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../kexec.h"
#include "../../kexec-elf.h"
#include "../../crashdump.h"
#include "crashdump-arm.h"

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ELFDATANATIVE ELFDATA2LSB
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ELFDATANATIVE ELFDATA2MSB
#else
#error "Unknown machine endian"
#endif

/*
 * Used to save various memory ranges/regions needed for the captured
 * kernel to boot. (lime memmap= option in other archs)
 */
static struct memory_range crash_memory_ranges[CRASH_MAX_MEMORY_RANGES];
struct memory_ranges usablemem_rgns = {
    .size = 0,
    .ranges = crash_memory_ranges,
};

/* memory range reserved for crashkernel */
static struct memory_range crash_reserved_mem;

static struct crash_elf_info elf_info = {
	.class		= ELFCLASS32,
	.data		= ELFDATANATIVE,
	.machine	= EM_ARM,
	.page_offset	= DEFAULT_PAGE_OFFSET,
};

unsigned long phys_offset;
extern unsigned long long user_page_offset;

/* Retrieve kernel _stext symbol virtual address from /proc/kallsyms */
static unsigned long long get_kernel_stext_sym(void)
{
	const char *kallsyms = "/proc/kallsyms";
	const char *stext = "_stext";
	char sym[128];
	char line[128];
	FILE *fp;
	unsigned long long vaddr = 0;
	char type;

	fp = fopen(kallsyms, "r");
	if (!fp) {
		fprintf(stderr, "Cannot open %s\n", kallsyms);
		return 0;
	}

	while(fgets(line, sizeof(line), fp) != NULL) {
		unsigned long long addr;

		if (sscanf(line, "%Lx %c %s", &addr, &type, sym) != 3)
			continue;

		if (strcmp(sym, stext) == 0) {
			dbgprintf("kernel symbol %s vaddr = %#llx\n", stext, addr);
			vaddr = addr;
			break;
		}
	}

	fclose(fp);

	if (vaddr == 0)
		fprintf(stderr, "Cannot get kernel %s symbol address\n", stext);

	return vaddr;
}

static int get_kernel_page_offset(struct kexec_info *info,
		struct crash_elf_info *elf_info)
{
	unsigned long long stext_sym_addr = get_kernel_stext_sym();
	if (stext_sym_addr == 0) {
		if (user_page_offset != (-1ULL)) {
			elf_info->page_offset = user_page_offset;
			dbgprintf("Unable to get _stext symbol from /proc/kallsyms, "
					"use user provided vaule: %llx\n",
					elf_info->page_offset);
			return 0;
		}
		elf_info->page_offset = (unsigned long long)DEFAULT_PAGE_OFFSET;
		dbgprintf("Unable to get _stext symbol from /proc/kallsyms, "
				"use default: %llx\n",
				elf_info->page_offset);
		return 0;
	} else if ((user_page_offset != (-1ULL)) &&
			(user_page_offset != stext_sym_addr)) {
		fprintf(stderr, "PAGE_OFFSET is set to %llx "
				"instead of user provided value %llx\n",
				stext_sym_addr & (~KVBASE_MASK),
				user_page_offset);
	}
	elf_info->page_offset = stext_sym_addr & (~KVBASE_MASK);
	dbgprintf("page_offset is set to %llx\n", elf_info->page_offset);
	return 0;
}

/**
 * crash_range_callback() - callback called for each iomem region
 * @data: not used
 * @nr: not used
 * @str: name of the memory region
 * @base: start address of the memory region
 * @length: size of the memory region
 *
 * This function is called once for each memory region found in /proc/iomem. It
 * locates system RAM and crashkernel reserved memory and places these to
 * variables: @crash_memory_ranges and @crash_reserved_mem. Number of memory
 * regions is placed in @crash_memory_nr_ranges.
 */
static int crash_range_callback(void *UNUSED(data), int UNUSED(nr),
				char *str, unsigned long long base,
				unsigned long long length)
{
	struct memory_range *range;

	if (usablemem_rgns.size >= CRASH_MAX_MEMORY_RANGES)
		return 1;

	range = usablemem_rgns.ranges + usablemem_rgns.size;

	if (strncmp(str, "System RAM\n", 11) == 0) {
		range->start = base;
		range->end = base + length - 1;
		range->type = RANGE_RAM;
		usablemem_rgns.size++;
	} else if (strncmp(str, "Crash kernel\n", 13) == 0) {
		crash_reserved_mem.start = base;
		crash_reserved_mem.end = base + length - 1;
		crash_reserved_mem.type = RANGE_RAM;
	}

	return 0;
}

/**
 * crash_exclude_range() - excludes memory region reserved for crashkernel
 *
 * Function locates where crashkernel reserved memory is and removes that region
 * from the available memory regions.
 */
static void crash_exclude_range(void)
{
	const struct memory_range *range = &crash_reserved_mem;
	int i;

	for (i = 0; i < usablemem_rgns.size; i++) {
		struct memory_range *r = usablemem_rgns.ranges + i;

		/*
		 * We assume that crash area is fully contained in
		 * some larger memory area.
		 */
		if (r->start <= range->start && r->end >= range->end) {
			struct memory_range *new;
			/*
			 * Let's split this area into 2 smaller ones and
			 * remove excluded range from between. First create
			 * new entry for the remaining area.
			 */
			new = usablemem_rgns.ranges + usablemem_rgns.size;
			new->start = range->end + 1;
			new->end = r->end;
			usablemem_rgns.size++;
			/*
			 * Next update this area to end before excluded range.
			 */
			r->end = range->start - 1;
			break;
		}
	}
}

static int range_cmp(const void *a1, const void *a2)
{
	const struct memory_range *r1 = a1;
	const struct memory_range *r2 = a2;

	if (r1->start > r2->start)
		return 1;
	if (r1->start < r2->start)
		return -1;

	return 0;
}

/**
 * crash_get_memory_ranges() - read system physical memory
 *
 * Function reads through system physical memory and stores found memory regions
 * in @crash_memory_ranges. Number of memory regions found is placed in
 * @crash_memory_nr_ranges. Regions are sorted in ascending order.
 *
 * Returns %0 in case of success and %-1 otherwise (errno is set).
 */
static int crash_get_memory_ranges(void)
{
	/*
	 * First read all memory regions that can be considered as
	 * system memory including the crash area.
	 */
	kexec_iomem_for_each_line(NULL, crash_range_callback, NULL);

	if (usablemem_rgns.size < 1) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * Exclude memory reserved for crashkernel (this may result a split memory
	 * region).
	 */
	crash_exclude_range();

	/*
	 * Make sure that the memory regions are sorted.
	 */
	qsort(usablemem_rgns.ranges, usablemem_rgns.size,
	      sizeof(*usablemem_rgns.ranges), range_cmp);

	return 0;
}

/**
 * cmdline_add_elfcorehdr() - adds elfcorehdr= to @cmdline
 * @cmdline: buffer where parameter is placed
 * @elfcorehdr: physical address of elfcorehdr
 *
 * Function appends 'elfcorehdr=start' at the end of the command line given in
 * @cmdline. Note that @cmdline must be at least %COMMAND_LINE_SIZE bytes long
 * (inclunding %NUL).
 */
static void cmdline_add_elfcorehdr(char *cmdline, unsigned long elfcorehdr)
{
	char buf[COMMAND_LINE_SIZE];
	int buflen;

	buflen = snprintf(buf, sizeof(buf), "%s elfcorehdr=%#lx",
			  cmdline, elfcorehdr);
	if (buflen < 0)
		die("Failed to construct elfcorehdr= command line parameter\n");
	if (buflen >= sizeof(buf))
		die("Command line overflow\n");

	(void) strncpy(cmdline, buf, COMMAND_LINE_SIZE);
	cmdline[COMMAND_LINE_SIZE - 1] = '\0';
}

/**
 * cmdline_add_mem() - adds mem= parameter to kernel command line
 * @cmdline: buffer where parameter is placed
 * @size: size of the kernel reserved memory (in bytes)
 *
 * This function appends 'mem=size' at the end of the command line given in
 * @cmdline. Note that @cmdline must be at least %COMMAND_LINE_SIZE bytes long
 * (including %NUL).
 */
static void cmdline_add_mem(char *cmdline, unsigned long size)
{
	char buf[COMMAND_LINE_SIZE];
	int buflen;

	buflen = snprintf(buf, sizeof(buf), "%s mem=%ldK", cmdline, size >> 10);
	if (buflen < 0)
		die("Failed to construct mem= command line parameter\n");
	if (buflen >= sizeof(buf))
		die("Command line overflow\n");

	(void) strncpy(cmdline, buf, COMMAND_LINE_SIZE);
	cmdline[COMMAND_LINE_SIZE - 1] = '\0';
}

static unsigned long long range_size(const struct memory_range *r)
{
	return r->end - r->start + 1;
}

static void dump_memory_ranges(void)
{
	int i;

	if (!kexec_debug)
		return;

	dbgprintf("crashkernel: [%#llx - %#llx] (%ldM)\n",
		  crash_reserved_mem.start, crash_reserved_mem.end,
		  (unsigned long)range_size(&crash_reserved_mem) >> 20);

	for (i = 0; i < usablemem_rgns.size; i++) {
		struct memory_range *r = usablemem_rgns.ranges + i;
		dbgprintf("memory range: [%#llx - %#llx] (%ldM)\n",
			  r->start, r->end, (unsigned long)range_size(r) >> 20);
	}
}

/**
 * load_crashdump_segments() - loads additional segments needed for kdump
 * @info: kexec info structure
 * @mod_cmdline: kernel command line
 *
 * This function loads additional segments which are needed for the dump capture
 * kernel. It also updates kernel command line passed in @mod_cmdline to have
 * right parameters for the dump capture kernel.
 *
 * Return %0 in case of success and %-1 in case of error.
 */
int load_crashdump_segments(struct kexec_info *info, char *mod_cmdline)
{
	unsigned long elfcorehdr;
	unsigned long bufsz;
	void *buf;
	int err;
	int last_ranges;

	/*
	 * First fetch all the memory (RAM) ranges that we are going to pass to
	 * the crashdump kernel during panic.
	 */
	err = crash_get_memory_ranges();
	if (err)
		return err;

	/*
	 * Now that we have memory regions sorted, we can use first memory
	 * region as PHYS_OFFSET.
	 */
	phys_offset = usablemem_rgns.ranges->start;
	dbgprintf("phys_offset: %#lx\n", phys_offset);

	if (get_kernel_page_offset(info, &elf_info))
		return -1;

	last_ranges = usablemem_rgns.size - 1;
	if (last_ranges < 0)
		last_ranges = 0;

	if (crash_memory_ranges[last_ranges].end > ULONG_MAX) {

		/* for support LPAE enabled kernel*/
		elf_info.class = ELFCLASS64;

		err = crash_create_elf64_headers(info, &elf_info,
					 usablemem_rgns.ranges,
					 usablemem_rgns.size, &buf, &bufsz,
					 ELF_CORE_HEADER_ALIGN);
	} else {
		err = crash_create_elf32_headers(info, &elf_info,
					 usablemem_rgns.ranges,
					 usablemem_rgns.size, &buf, &bufsz,
					 ELF_CORE_HEADER_ALIGN);
	}
	if (err)
		return err;

	/*
	 * We allocate ELF core header from the end of the memory area reserved
	 * for the crashkernel. We align the header to SECTION_SIZE (which is
	 * 1MB) so that available memory passed in kernel command line will be
	 * aligned to 1MB. This is because kernel create_mapping() wants memory
	 * regions to be aligned to SECTION_SIZE.
	 */
	elfcorehdr = add_buffer_phys_virt(info, buf, bufsz, bufsz, 1 << 20,
					  crash_reserved_mem.start,
					  crash_reserved_mem.end, -1, 0);

	dbgprintf("elfcorehdr: %#lx\n", elfcorehdr);
	cmdline_add_elfcorehdr(mod_cmdline, elfcorehdr);

	/*
	 * Add 'mem=size' parameter to dump capture kernel command line. This
	 * prevents the dump capture kernel from using any other memory regions
	 * which belong to the primary kernel.
	 */
	cmdline_add_mem(mod_cmdline, elfcorehdr - crash_reserved_mem.start);

	dump_memory_ranges();
	dbgprintf("kernel command line: \"%s\"\n", mod_cmdline);

	return 0;
}

int is_crashkernel_mem_reserved(void)
{
	uint64_t start, end;

	if (parse_iomem_single("Crash kernel\n", &start, &end) == 0)
		return start != end;

	return 0;
}
