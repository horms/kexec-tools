/*
 * kexec: Linux boots Linux
 *
 * 2005 (C) IBM Corporation.
 * 2008 (C) MontaVista Software, Inc.
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
#include "kexec-mips.h"
#include "crashdump-mips.h"
#include "unused.h"

/* Stores a sorted list of RAM memory ranges for which to create elf headers.
 * A separate program header is created for backup region */
static struct memory_range crash_memory_range[CRASH_MAX_MEMORY_RANGES];

/* Memory region reserved for storing panic kernel and other data. */
static struct memory_range crash_reserved_mem;

/*
 * To store the memory size of the first kernel and this value will be
 * passed to the second kernel as command line (savemaxmem=xM).
 * The second kernel will be calculated saved_max_pfn based on this
 * variable.
 */
unsigned long long saved_max_mem;

/* Removes crash reserve region from list of memory chunks for whom elf program
 * headers have to be created. Assuming crash reserve region to be a single
 * continuous area fully contained inside one of the memory chunks */
static int exclude_crash_reserve_region(int *nr_ranges)
{
	int i, j, tidx = -1;
	unsigned long long cstart, cend;
	struct memory_range temp_region = {
		.start = 0,
		.end = 0
	};

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
	const char iomem[] = "/proc/iomem";
	int i, memory_ranges = 0;
	char line[MAX_LINE];
	FILE *fp;
	unsigned long long start, end;

	fp = fopen(iomem, "r");
	if (!fp) {
		fprintf(stderr, "Cannot open %s: %s\n",
			iomem, strerror(errno));
		return -1;
	}
	/* Separate segment for backup region */
	crash_memory_range[0].start = BACKUP_SRC_START;
	crash_memory_range[0].end = BACKUP_SRC_END;
	crash_memory_range[0].type = RANGE_RAM;
	memory_ranges++;

	while (fgets(line, sizeof(line), fp) != 0) {
		char *str;
		int type, consumed, count;
		if (memory_ranges >= CRASH_MAX_MEMORY_RANGES)
			break;
		count = sscanf(line, "%Lx-%Lx : %n",
			&start, &end, &consumed);
		if (count != 2)
			continue;
		str = line + consumed;

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
		} else
			continue;

		if (start == BACKUP_SRC_START && end >= (BACKUP_SRC_END + 1))
			start = BACKUP_SRC_END + 1;

		crash_memory_range[memory_ranges].start = start;
		crash_memory_range[memory_ranges].end = end;
		crash_memory_range[memory_ranges].type = type;
		memory_ranges++;

		/* Segregate linearly mapped region. */
		if ((MAXMEM - 1) >= start && (MAXMEM - 1) <= end) {
			crash_memory_range[memory_ranges - 1].end = MAXMEM - 1;

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

	for (i = 0; i < memory_ranges; i++)
		if (saved_max_mem < crash_memory_range[i].end)
			saved_max_mem = crash_memory_range[i].end + 1;

	*range = crash_memory_range;
	*ranges = memory_ranges;
	return 0;
}

/* Converts unsigned long to ascii string. */
static void ultoa(unsigned long i, char *str)
{
	int j = 0, k;
	char tmp;

	do {
		str[j++] = i % 10 + '0';
	} while ((i /= 10) > 0);
	str[j] = '\0';

	/* Reverse the string. */
	for (j = 0, k = strlen(str) - 1; j < k; j++, k--) {
		tmp = str[k];
		str[k] = str[j];
		str[j] = tmp;
	}
}

/* Adds the appropriate mem= options to command line, indicating the
 * memory region the new kernel can use to boot into. */
static int cmdline_add_mem(char *cmdline, unsigned long addr,
		unsigned long size)
{
	int cmdlen, len;
	char str[50], *ptr;

	addr = addr/1024;
	size = size/1024;
	ptr = str;
	strcpy(str, " mem=");
	ptr += strlen(str);
	ultoa(size, ptr);
	strcat(str, "K@");
	ptr = str + strlen(str);
	ultoa(addr, ptr);
	strcat(str, "K");
	len = strlen(str);
	cmdlen = strlen(cmdline) + len;
	if (cmdlen > (COMMAND_LINE_SIZE - 1))
		die("Command line overflow\n");
	strcat(cmdline, str);

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
	return 0;
}

/* Adds the savemaxmem= command line parameter to command line. */
static int cmdline_add_savemaxmem(char *cmdline, unsigned long long addr)
{
	int cmdlen, len, align = 1024;
	char str[30], *ptr;

	/* Passing in savemaxmem=xxxM format. Saves space required in cmdline.*/
	addr = addr/(align*align);
	ptr = str;
	strcpy(str, " savemaxmem=");
	ptr += strlen(str);
	ultoa(addr, ptr);
	strcat(str, "M");
	len = strlen(str);
	cmdlen = strlen(cmdline) + len;
	if (cmdlen > (COMMAND_LINE_SIZE - 1))
		die("Command line overflow\n");
	strcat(cmdline, str);
	return 0;
}

#ifdef __mips64
static struct crash_elf_info elf_info64 = {
	class: ELFCLASS64,
	data : ELFDATA2MSB,
	machine : EM_MIPS,
	backup_src_start : BACKUP_SRC_START,
	backup_src_end : BACKUP_SRC_END,
	page_offset : PAGE_OFFSET,
	lowmem_limit : MAXMEM,
};
#endif
static struct crash_elf_info elf_info32 = {
	class: ELFCLASS32,
	data : ELFDATA2MSB,
	machine : EM_MIPS,
	backup_src_start : BACKUP_SRC_START,
	backup_src_end : BACKUP_SRC_END,
	page_offset : PAGE_OFFSET,
	lowmem_limit : MAXMEM,
};

/* Loads additional segments in case of a panic kernel is being loaded.
 * One segment for backup region, another segment for storing elf headers
 * for crash memory image.
 */
int load_crashdump_segments(struct kexec_info *info, char* mod_cmdline,
				unsigned long UNUSED(max_addr),
				unsigned long UNUSED(min_base))
{
	void *tmp;
	unsigned long sz, elfcorehdr;
	int nr_ranges, align = 1024;
	struct memory_range *mem_range;

	if (get_crash_memory_ranges(&mem_range, &nr_ranges) < 0)
		return -1;

	/* Create a backup region segment to store backup data*/
	sz = (BACKUP_SRC_SIZE + align - 1) & ~(align - 1);
	tmp = xmalloc(sz);
	memset(tmp, 0, sz);
	info->backup_start = add_buffer(info, tmp, sz, sz, align,
				crash_reserved_mem.start,
				crash_reserved_mem.end, -1);

#ifdef __mips64
	/* Create elf header segment and store crash image data. */
	if (arch_options.core_header_type == CORE_TYPE_ELF64) {
		if (crash_create_elf64_headers(info, &elf_info64,
			crash_memory_range, nr_ranges,
			&tmp, &sz,
			ELF_CORE_HEADER_ALIGN) < 0)
			return -1;
	} else {
		if (crash_create_elf32_headers(info, &elf_info32,
			crash_memory_range, nr_ranges,
			&tmp, &sz,
			ELF_CORE_HEADER_ALIGN) < 0)
			return -1;
	}
#else
	if (crash_create_elf32_headers(info, &elf_info32,
		crash_memory_range, nr_ranges,
		&tmp, &sz,
		ELF_CORE_HEADER_ALIGN) < 0)
		return -1;
#endif
	elfcorehdr = add_buffer(info, tmp, sz, sz, align,
		crash_reserved_mem.start,
		crash_reserved_mem.end, -1);

	/*
	 * backup segment is after elfcorehdr, so use elfcorehdr as top of
	 * kernel's available memory
	 */
	cmdline_add_mem(mod_cmdline, crash_reserved_mem.start,
		elfcorehdr - crash_reserved_mem.start);
	cmdline_add_elfcorehdr(mod_cmdline, elfcorehdr);
	cmdline_add_savemaxmem(mod_cmdline, saved_max_mem);

#ifdef DEBUG
	printf("CRASH MEMORY RANGES:\n");
	printf("%016Lx-%016Lx\n", crash_reserved_mem.start,
			crash_reserved_mem.end);
#endif
	return 0;
}

int is_crashkernel_mem_reserved(void)
{
	uint64_t start, end;

	return parse_iomem_single("Crash kernel\n", &start, &end) == 0 ?
		(start != end) : 0;
}

