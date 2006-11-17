/*
 * kexec: crashdum support
 * Copyright (C) 2005-2006 Zou Nan hai <nanhai.zou@intel.com> Intel Corp
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
#include "../../kexec.h"
#include "../../kexec-elf.h"
#include "../../kexec-syscall.h"
#include "kexec-ia64.h"
#include "crashdump-ia64.h"

int memory_ranges = 0;
#define LOAD_OFFSET 	(0xa000000000000000UL + 0x100000000UL - kernel_code_start)
#define MAX_LINE        160
/* Stores a sorted list of RAM memory ranges for which to create elf headers.
 * A separate program header is created for backup region */
static struct memory_range crash_memory_range[CRASH_MAX_MEMORY_RANGES];
/* Memory region reserved for storing panic kernel and other data. */
static struct memory_range crash_reserved_mem;
unsigned long elfcorehdr;
static unsigned long kernel_code_start;
struct loaded_segment {
        unsigned long start;
        unsigned long end;
	unsigned long reserved;
};

#define MAX_LOAD_SEGMENTS	128
struct loaded_segment loaded_segments[MAX_LOAD_SEGMENTS];

unsigned long loaded_segments_num, loaded_segments_base;
static int seg_comp(const void *a, const void *b)
{
        const struct loaded_segment *x = a, *y = b;
        /* avoid overflow */
        if (x->start > y->start) return 1;
	if (x->start < y->start) return -1;
	return 0;
}

/* purgatory code need this info to patch the EFI memmap
 */
static void add_loaded_segments_info(struct kexec_info *info,
	struct mem_ehdr *ehdr, unsigned long max_addr)
{
	 int i;
         for(i = 0; i < ehdr->e_phnum; i++) {
                unsigned long start, end;
                struct mem_phdr *phdr;
                phdr = &ehdr->e_phdr[i];
                if (phdr->p_type != PT_LOAD)
                        continue;
                start = phdr->p_paddr;
                end = phdr->p_paddr + phdr->p_memsz;

		loaded_segments[loaded_segments_num].start =
                        start&~(ELF_PAGE_SIZE-1);
                loaded_segments[loaded_segments_num].end =
                        (end + ELF_PAGE_SIZE - 1)&~(ELF_PAGE_SIZE - 1);
		loaded_segments[loaded_segments_num].reserved = 0;
		loaded_segments_num++;
	}
}

static int get_crash_notes_section_addr(int cpu, unsigned long *addr,
					unsigned long *len)
{
        char crash_notes[128];
        char line[MAX_LINE];
        FILE *fp;
	sprintf(crash_notes, "/sys/devices/system/cpu/cpu%d/crash_notes", cpu);
        fp = fopen(crash_notes, "r");
        if (!fp) {
                fprintf(stderr, "Cannot open %s: %s\n",
                        crash_notes, strerror(errno));
                fprintf(stderr, "Try mounting sysfs\n");
                return -1;
        }
	if (fscanf(fp, "%lx", addr) != 1) {
		*addr = 0;
		return -1;
	}

	*len = MAX_NOTE_BYTES;

        return 0;
}

/* Removes crash reserve region from list of memory chunks for whom elf program
 * headers have to be created. Assuming crash reserve region to be a single
 * continuous area fully contained inside one of the memory chunks */
static int exclude_crash_reserve_region(int *nr_ranges)
{
	int i, j, tidx = -1;
	unsigned long cstart, cend;
	struct memory_range temp_region;

	/* Crash reserved region. */
	cstart = crash_reserved_mem.start;
	cend = crash_reserved_mem.end;

	for (i = 0; i < (*nr_ranges); i++) {
		unsigned long mstart, mend;
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

static int prepare_crash_memory_elf64_headers(struct kexec_info *info,
                                                void *buf, unsigned long size)
{
	Elf64_Ehdr *elf;
	Elf64_Phdr *phdr;
	int i;
	long int nr_cpus = 0;
	char *bufp = buf;
	unsigned long notes_addr, notes_offset, notes_len;

	/* Setup ELF Header*/
	elf = (Elf64_Ehdr *) bufp;
	bufp += sizeof(Elf64_Ehdr);
	memcpy(elf->e_ident, ELFMAG, SELFMAG);
	elf->e_ident[EI_CLASS]  = ELFCLASS64;
	elf->e_ident[EI_DATA]   = ELFDATA2LSB;
	elf->e_ident[EI_VERSION]= EV_CURRENT;
	elf->e_ident[EI_OSABI] = ELFOSABI_NONE;
	memset(elf->e_ident+EI_PAD, 0, EI_NIDENT-EI_PAD);
	elf->e_type     = ET_CORE;
	elf->e_machine  = EM_IA_64;
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
	if (nr_cpus < 0) {
		return -1;
	}

        for (i = 0; i < nr_cpus; i++) {
		if (get_crash_notes_section_addr (i, &notes_addr,
						  &notes_len) < 0)
                	break;
		notes_offset = notes_addr;
		phdr = (Elf64_Phdr *) bufp;
                bufp += sizeof(Elf64_Phdr);
                phdr->p_type    = PT_NOTE;
                phdr->p_flags   = 0;
                phdr->p_offset  = notes_offset;
                phdr->p_vaddr   = phdr->p_paddr = notes_offset;
                phdr->p_filesz  = phdr->p_memsz = notes_len;
                /* Do we need any alignment of segments? */
                phdr->p_align   = 0;

                /* Increment number of program headers. */
                (elf->e_phnum)++;
        }

	for (i = 0; i < memory_ranges; i++) {
		unsigned long mstart, mend;
		mstart = crash_memory_range[i].start;
		mend = crash_memory_range[i].end;
		if (!mstart && !mend)
			break;
		phdr = (Elf64_Phdr *) bufp;
		bufp += sizeof(Elf64_Phdr);
		phdr->p_type    = PT_LOAD;
		phdr->p_flags   = PF_R|PF_W|PF_X;
		phdr->p_offset  = mstart;
		/*add region 5 mapping for kernel*/
		if (kernel_code_start >= mstart && kernel_code_start < mend) {
			phdr->p_vaddr = mstart + LOAD_OFFSET;
			phdr->p_paddr = mstart;
			phdr->p_filesz  = phdr->p_memsz = mend - mstart + 1;
			phdr->p_align   = 0;
			(elf->e_phnum)++;

			phdr = (Elf64_Phdr *) bufp;
			bufp += sizeof(Elf64_Phdr);
			phdr->p_type    = PT_LOAD;
			phdr->p_flags   = PF_R|PF_W|PF_X;
			phdr->p_offset  = mstart;
		}
		phdr->p_vaddr = mstart + PAGE_OFFSET;
		phdr->p_paddr = mstart;
		phdr->p_filesz  = phdr->p_memsz = mend - mstart + 1;
		phdr->p_align   = 0;
		(elf->e_phnum)++;
	}
	return 0;
}

static int get_crash_memory_ranges(struct memory_range **range, int *ranges)
{
	const char iomem[]= "/proc/iomem";
        char line[MAX_LINE];
        FILE *fp;
        unsigned long start, end;

        fp = fopen(iomem, "r");
        if (!fp) {
                fprintf(stderr, "Cannot open %s: %s\n",
                        iomem, strerror(errno));
                return -1;
        }
	while(fgets(line, sizeof(line), fp) != 0) {
		char *str;
		int type, consumed, count;
		if (memory_ranges >= CRASH_MAX_MEMORY_RANGES)
			break;
		count = sscanf(line, "%lx-%lx : %n",
				&start, &end, &consumed);
		str = line + consumed;
		if (count != 2)
			continue;

		if (memcmp(str, "System RAM\n", 11) == 0) {
			type = RANGE_RAM;
		} else if (memcmp(str, "Crash kernel\n", 13) == 0) {
			/* Reserved memory region. New kernel can
			 * use this region to boot into. */
			crash_reserved_mem.start = start;
			crash_reserved_mem.end = end;
			crash_reserved_mem.type = RANGE_RAM;
			continue;
		}
		else if (memcmp(str, "Kernel code\n", 12) == 0) {
			kernel_code_start = start;
			continue;
		}else
			continue;
		crash_memory_range[memory_ranges].start = start;
		crash_memory_range[memory_ranges].end = end;
		crash_memory_range[memory_ranges].type = type;
		memory_ranges++;
	}
        fclose(fp);
	if (exclude_crash_reserve_region(&memory_ranges) < 0)
		return -1;
	*ranges = memory_ranges;
	return 0;
}

static void
cmdline_add_elfcorehdr(char **cmdline, unsigned long addr)
{
	char *str = *cmdline;
	char buf[64];
	size_t len;
	sprintf(buf, " elfcorehdr=%ldK", addr/1024);
	len = strlen(str) + strlen(buf) + 1;
	str = xmalloc(len);
	sprintf(str, "%s%s", *cmdline, buf);
	*cmdline = str;
}

int load_crashdump_segments(struct kexec_info *info, struct mem_ehdr *ehdr,
                            unsigned long max_addr, unsigned long min_base,
			    char **cmdline)
{
	//struct memory_range *mem_range, *memmap_p;
	struct memory_range *mem_range;
	int nr_ranges;
	size_t size;
	void *tmp;
	if (info->kexec_flags & KEXEC_ON_CRASH ) {
		if (get_crash_memory_ranges(&mem_range, &nr_ranges) == 0) {
			size =  sizeof(Elf64_Ehdr) +
				(nr_ranges + 1) * sizeof(Elf64_Phdr);
			size = (size + EFI_PAGE_SIZE - 1) & ~(EFI_PAGE_SIZE - 1);
			tmp = xmalloc(size);
			memset(tmp, 0, size);
			if (prepare_crash_memory_elf64_headers(info, tmp, size) < 0)
				return -1;
			elfcorehdr = add_buffer(info, tmp, size, size, EFI_PAGE_SIZE, min_base,
					max_addr, -1);
			loaded_segments[loaded_segments_num].start = elfcorehdr;
			loaded_segments[loaded_segments_num].end = elfcorehdr + size;
			loaded_segments[loaded_segments_num].reserved = 1;
			loaded_segments_num++;
			cmdline_add_elfcorehdr(cmdline, elfcorehdr);
		}
	}
	add_loaded_segments_info(info, ehdr, max_addr);
	size = sizeof(struct loaded_segment) * loaded_segments_num;
	qsort(loaded_segments, loaded_segments_num,
                        sizeof(struct loaded_segment), seg_comp);
        loaded_segments_base = add_buffer(info, loaded_segments,
                        size, size, 16, 0, max_addr, -1);

        elf_rel_set_symbol(&info->rhdr, "__loaded_segments",
                        &loaded_segments_base, sizeof(long));
        elf_rel_set_symbol(&info->rhdr, "__loaded_segments_num",
                         &loaded_segments_num, sizeof(long));
	return 0;
}

/*
 * Adding a dummy function, so that build on IA64 will not break.
 * Need to implement the actual checking code
 */
int is_crashkernel_mem_reserved(void)
{
	return 1;
}
