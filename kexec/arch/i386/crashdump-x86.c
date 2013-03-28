/*
 * kexec: Linux boots Linux
 *
 * Created by: Vivek Goyal (vgoyal@in.ibm.com)
 * old x86_64 version Created by: Murali M Chakravarthy (muralim@in.ibm.com)
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

#define _XOPEN_SOURCE	600
#define _BSD_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <elf.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../../kexec.h"
#include "../../kexec-elf.h"
#include "../../kexec-syscall.h"
#include "../../firmware_memmap.h"
#include "../../crashdump.h"
#include "kexec-x86.h"
#include "crashdump-x86.h"

#ifdef HAVE_LIBXENCTRL
#ifdef HAVE_XC_GET_MACHINE_MEMORY_MAP
#include <xenctrl.h>
#else
#define __XEN_TOOLS__	1
#include <xen/xen.h>
#include <xen/memory.h>
#include <xen/sys/privcmd.h>
#endif /* HAVE_XC_GET_MACHINE_MEMORY_MAP */
#endif /* HAVE_LIBXENCTRL */

#include <x86/x86-linux.h>

extern struct arch_options_t arch_options;

static int get_kernel_page_offset(struct kexec_info *UNUSED(info),
				  struct crash_elf_info *elf_info)
{
	int kv;

	if (elf_info->machine == EM_X86_64) {
		kv = kernel_version();
		if (kv < 0)
			return -1;

		if (kv < KERNEL_VERSION(2, 6, 27))
			elf_info->page_offset = X86_64_PAGE_OFFSET_PRE_2_6_27;
		else
			elf_info->page_offset = X86_64_PAGE_OFFSET;
	}
	else if (elf_info->machine == EM_386) {
		elf_info->page_offset = X86_PAGE_OFFSET;
	}

	return 0;
}

#define X86_64_KERN_VADDR_ALIGN	0x100000	/* 1MB */

/* Read kernel physical load addr from the file returned by proc_iomem()
 * (Kernel Code) and store in kexec_info */
static int get_kernel_paddr(struct kexec_info *UNUSED(info),
			    struct crash_elf_info *elf_info)
{
	uint64_t start;

	if (elf_info->machine != EM_X86_64)
		return 0;

	if (xen_present()) /* Kernel not entity mapped under Xen */
		return 0;

	if (parse_iomem_single("Kernel code\n", &start, NULL) == 0) {
		elf_info->kern_paddr_start = start;
		dbgprintf("kernel load physical addr start = 0x%016Lx\n",
			  (unsigned long long)start);
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

static int get_kernel_vaddr_and_size(struct kexec_info *UNUSED(info),
				     struct crash_elf_info *elf_info)
{
	int result;
	const char kcore[] = "/proc/kcore";
	char *buf;
	struct mem_ehdr ehdr;
	struct mem_phdr *phdr, *end_phdr;
	int align;
	unsigned long size;
	uint32_t elf_flags = 0;

	if (elf_info->machine != EM_X86_64)
		return 0;

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
		/* Perhaps KCORE_ELF_HEADERS_SIZE is too small? */
		fprintf(stderr, "ELF core (kcore) parse failed\n");
		return -1;
	}

	/* Traverse through the Elf headers and find the region where
	 * kernel is mapped. */
	end_phdr = &ehdr.e_phdr[ehdr.e_phnum];
	for(phdr = ehdr.e_phdr; phdr != end_phdr; phdr++) {
		if (phdr->p_type == PT_LOAD) {
			unsigned long long saddr = phdr->p_vaddr;
			unsigned long long eaddr = phdr->p_vaddr + phdr->p_memsz;
			unsigned long long size;

			/* Look for kernel text mapping header. */
			if ((saddr >= X86_64__START_KERNEL_map) &&
			    (eaddr <= X86_64__START_KERNEL_map + X86_64_KERNEL_TEXT_SIZE)) {
				saddr = _ALIGN_DOWN(saddr, X86_64_KERN_VADDR_ALIGN);
				elf_info->kern_vaddr_start = saddr;
				size = eaddr - saddr;
				/* Align size to page size boundary. */
				size = _ALIGN(size, align);
				elf_info->kern_size = size;
				dbgprintf("kernel vaddr = 0x%llx size = 0x%llx\n",
					saddr, size);
				return 0;
			}
		}
	}
	fprintf(stderr, "Can't find kernel text map area from kcore\n");
	return -1;
}

/* Forward Declaration. */
static void segregate_lowmem_region(int *nr_ranges, unsigned long lowmem_limit);
static int exclude_region(int *nr_ranges, uint64_t start, uint64_t end);

/* Stores a sorted list of RAM memory ranges for which to create elf headers.
 * A separate program header is created for backup region */
static struct memory_range crash_memory_range[CRASH_MAX_MEMORY_RANGES];

/* Memory region reserved for storing panic kernel and other data. */
static struct memory_range crash_reserved_mem;
/* under 4G parts */
static struct memory_range crash_reserved_low_mem;

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
static int get_crash_memory_ranges(struct memory_range **range, int *ranges,
				   int kexec_flags, unsigned long lowmem_limit)
{
	const char *iomem = proc_iomem();
	int memory_ranges = 0, gart = 0;
	char line[MAX_LINE];
	FILE *fp;
	unsigned long long start, end;
	uint64_t gart_start = 0, gart_end = 0;

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
		count = sscanf(line, "%Lx-%Lx : %n",
			&start, &end, &consumed);
		if (count != 2)
			continue;
		str = line + consumed;
		dbgprintf("%016Lx-%016Lx : %s",
			start, end, str);
		/* Only Dumping memory of type System RAM. */
		if (memcmp(str, "System RAM\n", 11) == 0) {
			type = RANGE_RAM;
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
		} else if(memcmp(str,"reserved\n", 9) == 0 ) {
			type = RANGE_RESERVED;
		} else if (memcmp(str, "GART\n", 5) == 0) {
			gart_start = start;
			gart_end = end;
			gart = 1;
			continue;
		} else {
			continue;
		}

		crash_memory_range[memory_ranges].start = start;
		crash_memory_range[memory_ranges].end = end;
		crash_memory_range[memory_ranges].type = type;

		segregate_lowmem_region(&memory_ranges, lowmem_limit);

		memory_ranges++;
	}
	fclose(fp);
	if (kexec_flags & KEXEC_PRESERVE_CONTEXT) {
		int i;
		for (i = 0; i < memory_ranges; i++) {
			if (crash_memory_range[i].end > 0x0009ffff) {
				crash_reserved_mem.start = \
					crash_memory_range[i].start;
				break;
			}
		}
		if (crash_reserved_mem.start >= mem_max) {
			fprintf(stderr, "Too small mem_max: 0x%llx.\n",
				mem_max);
			return -1;
		}
		crash_reserved_mem.end = mem_max;
		crash_reserved_mem.type = RANGE_RAM;
	}
	if (exclude_region(&memory_ranges, crash_reserved_mem.start,
				crash_reserved_mem.end) < 0)
		return -1;
	if (crash_reserved_low_mem.start &&
	    exclude_region(&memory_ranges, crash_reserved_low_mem.start,
				crash_reserved_low_mem.end) < 0)
		return -1;
	if (gart) {
		/* exclude GART region if the system has one */
		if (exclude_region(&memory_ranges, gart_start, gart_end) < 0)
			return -1;
	}
	*range = crash_memory_range;
	*ranges = memory_ranges;

	return 0;
}

#ifdef HAVE_LIBXENCTRL
#ifdef HAVE_XC_GET_MACHINE_MEMORY_MAP
static int get_crash_memory_ranges_xen(struct memory_range **range,
					int *ranges, unsigned long lowmem_limit)
{
	int j, rc, ret = -1;
	struct e820entry e820entries[CRASH_MAX_MEMORY_RANGES];
	unsigned int i;
#ifdef XENCTRL_HAS_XC_INTERFACE
	xc_interface *xc;
#else
	int xc;
#endif

#ifdef XENCTRL_HAS_XC_INTERFACE
	xc = xc_interface_open(NULL, NULL, 0);

	if (!xc) {
		fprintf(stderr, "%s: Failed to open Xen control interface\n", __func__);
		goto err;
	}
#else
	xc = xc_interface_open();

	if (xc == -1) {
		fprintf(stderr, "%s: Failed to open Xen control interface\n", __func__);
		goto err;
	}
#endif

	rc = xc_get_machine_memory_map(xc, e820entries, CRASH_MAX_MEMORY_RANGES);

	if (rc < 0) {
		fprintf(stderr, "%s: xc_get_machine_memory_map: %s\n", __func__, strerror(-rc));
		goto err;
	}

	for (i = 0, j = 0; i < rc && j < CRASH_MAX_MEMORY_RANGES; ++i, ++j) {
		crash_memory_range[j].start = e820entries[i].addr;
		crash_memory_range[j].end = e820entries[i].addr + e820entries[i].size - 1;
		crash_memory_range[j].type = xen_e820_to_kexec_type(e820entries[i].type);
		segregate_lowmem_region(&j, lowmem_limit);
	}

	*range = crash_memory_range;
	*ranges = j;

	qsort(*range, *ranges, sizeof(struct memory_range), compare_ranges);

	if (exclude_region(ranges, crash_reserved_mem.start,
						crash_reserved_mem.end) < 0)
		goto err;

	ret = 0;

err:
	xc_interface_close(xc);

	return ret;
}
#else
static int get_crash_memory_ranges_xen(struct memory_range **range,
					int *ranges, unsigned long lowmem_limit)
{
	int fd, j, rc, ret = -1;
	privcmd_hypercall_t hypercall;
	struct e820entry *e820entries = NULL;
	struct xen_memory_map *xen_memory_map = NULL;
	unsigned int i;

	fd = open("/proc/xen/privcmd", O_RDWR);

	if (fd == -1) {
		fprintf(stderr, "%s: open(/proc/xen/privcmd): %m\n", __func__);
		goto err;
	}

	rc = posix_memalign((void **)&e820entries, getpagesize(),
			    sizeof(struct e820entry) * CRASH_MAX_MEMORY_RANGES);

	if (rc) {
		fprintf(stderr, "%s: posix_memalign(e820entries): %s\n", __func__, strerror(rc));
		e820entries = NULL;
		goto err;
	}

	rc = posix_memalign((void **)&xen_memory_map, getpagesize(),
			    sizeof(struct xen_memory_map));

	if (rc) {
		fprintf(stderr, "%s: posix_memalign(xen_memory_map): %s\n", __func__, strerror(rc));
		xen_memory_map = NULL;
		goto err;
	}

	if (mlock(e820entries, sizeof(struct e820entry) * CRASH_MAX_MEMORY_RANGES) == -1) {
		fprintf(stderr, "%s: mlock(e820entries): %m\n", __func__);
		goto err;
	}

	if (mlock(xen_memory_map, sizeof(struct xen_memory_map)) == -1) {
		fprintf(stderr, "%s: mlock(xen_memory_map): %m\n", __func__);
		goto err;
	}

	xen_memory_map->nr_entries = CRASH_MAX_MEMORY_RANGES;
	set_xen_guest_handle(xen_memory_map->buffer, e820entries);

	hypercall.op = __HYPERVISOR_memory_op;
	hypercall.arg[0] = XENMEM_machine_memory_map;
	hypercall.arg[1] = (__u64)xen_memory_map;

	rc = ioctl(fd, IOCTL_PRIVCMD_HYPERCALL, &hypercall);

	if (rc == -1) {
		fprintf(stderr, "%s: ioctl(IOCTL_PRIVCMD_HYPERCALL): %m\n", __func__);
		goto err;
	}

	for (i = 0, j = 0; i < xen_memory_map->nr_entries &&
				j < CRASH_MAX_MEMORY_RANGES; ++i, ++j) {
		crash_memory_range[j].start = e820entries[i].addr;
		crash_memory_range[j].end = e820entries[i].addr + e820entries[i].size - 1;
		crash_memory_range[j].type = xen_e820_to_kexec_type(e820entries[i].type);
		segregate_lowmem_region(&j, lowmem_limit);
	}

	*range = crash_memory_range;
	*ranges = j;

	qsort(*range, *ranges, sizeof(struct memory_range), compare_ranges);

	if (exclude_region(ranges, crash_reserved_mem.start,
						crash_reserved_mem.end) < 0)
		goto err;

	ret = 0;

err:
	munlock(xen_memory_map, sizeof(struct xen_memory_map));
	munlock(e820entries, sizeof(struct e820entry) * CRASH_MAX_MEMORY_RANGES);
	free(xen_memory_map);
	free(e820entries);
	close(fd);

	return ret;
}
#endif /* HAVE_XC_GET_MACHINE_MEMORY_MAP */
#else
static int get_crash_memory_ranges_xen(struct memory_range **range,
					int *ranges, unsigned long lowmem_limit)
{
	return 0;
}
#endif /* HAVE_LIBXENCTRL */

static void segregate_lowmem_region(int *nr_ranges, unsigned long lowmem_limit)
{
	unsigned long long end, start;
	unsigned type;

	start = crash_memory_range[*nr_ranges].start;
	end = crash_memory_range[*nr_ranges].end;
	type = crash_memory_range[*nr_ranges].type;

	if (!(lowmem_limit && lowmem_limit > start && lowmem_limit < end))
		return;

	crash_memory_range[*nr_ranges].end = lowmem_limit - 1;

	if (*nr_ranges >= CRASH_MAX_MEMORY_RANGES - 1)
		return;

	++*nr_ranges;

	crash_memory_range[*nr_ranges].start = lowmem_limit;
	crash_memory_range[*nr_ranges].end = end;
	crash_memory_range[*nr_ranges].type = type;
}

/* Removes crash reserve region from list of memory chunks for whom elf program
 * headers have to be created. Assuming crash reserve region to be a single
 * continuous area fully contained inside one of the memory chunks */
static int exclude_region(int *nr_ranges, uint64_t start, uint64_t end)
{
	int i, j, tidx = -1;
	struct memory_range temp_region = {0, 0, 0};


	for (i = 0; i < (*nr_ranges); i++) {
		unsigned long long mstart, mend;
		mstart = crash_memory_range[i].start;
		mend = crash_memory_range[i].end;
		if (start < mend && end > mstart) {
			if (start != mstart && end != mend) {
				/* Split memory region */
				crash_memory_range[i].end = start - 1;
				temp_region.start = end + 1;
				temp_region.end = mend;
				temp_region.type = RANGE_RAM;
				tidx = i+1;
			} else if (start != mstart)
				crash_memory_range[i].end = start - 1;
			else
				crash_memory_range[i].start = end + 1;
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
		crash_memory_range[tidx] = temp_region;
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

	dbgprintf("Memmap after adding segment\n");
	for (i = 0; i < CRASH_MAX_MEMMAP_NR;  i++) {
		mstart = memmap_p[i].start;
		mend = memmap_p[i].end;
		if (mstart == 0 && mend == 0)
			break;
		dbgprintf("%016llx - %016llx\n",
			mstart, mend);
	}

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
				temp_region.type = memmap_p[i].type;
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

	dbgprintf("Memmap after deleting segment\n");
	for (i = 0; i < CRASH_MAX_MEMMAP_NR;  i++) {
		mstart = memmap_p[i].start;
		mend = memmap_p[i].end;
		if (mstart == 0 && mend == 0) {
			break;
		}
		dbgprintf("%016llx - %016llx\n",
			mstart, mend);
	}

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

static void cmdline_add_memmap_internal(char *cmdline, unsigned long startk,
					unsigned long endk, int type)
{
	int cmdlen, len;
	char str_mmap[256], str_tmp[20];

	strcpy (str_mmap, " memmap=");
	ultoa((endk-startk), str_tmp);
	strcat (str_mmap, str_tmp);

	if (type == RANGE_RAM)
		strcat (str_mmap, "K@");
	else if (type == RANGE_RESERVED)
		strcat (str_mmap, "K$");
	else if (type == RANGE_ACPI || type == RANGE_ACPI_NVS)
		strcat (str_mmap, "K#");

	ultoa(startk, str_tmp);
	strcat (str_mmap, str_tmp);
	strcat (str_mmap, "K");
	len = strlen(str_mmap);
	cmdlen = strlen(cmdline) + len;
	if (cmdlen > (COMMAND_LINE_SIZE - 1))
		die("Command line overflow\n");
	strcat(cmdline, str_mmap);
}

/* Adds the appropriate memmap= options to command line, indicating the
 * memory regions the new kernel can use to boot into. */
static int cmdline_add_memmap(char *cmdline, struct memory_range *memmap_p)
{
	int i, cmdlen, len;
	unsigned long min_sizek = 100;
	char str_mmap[256];

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
		cmdline_add_memmap_internal(cmdline, startk, endk, RANGE_RAM);
	}

	dbgprintf("Command line after adding memmap\n");
	dbgprintf("%s\n", cmdline);

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

	dbgprintf("Command line after adding elfcorehdr\n");
	dbgprintf("%s\n", cmdline);

	return 0;
}


/*
 * This routine is specific to i386 architecture to maintain the
 * backward compatibility, other architectures can use the per
 * cpu version get_crash_notes_per_cpu() directly.
 */
static int get_crash_notes(int cpu, uint64_t *addr, uint64_t *len)
{
	const char *crash_notes = "/sys/kernel/crash_notes";
	char line[MAX_LINE];
	FILE *fp;
	unsigned long vaddr;
	int count;

	fp = fopen(crash_notes, "r");
	if (fp) {
		if (fgets(line, sizeof(line), fp) != 0) {
			count = sscanf(line, "%lx", &vaddr);
			if (count != 1)
				die("Cannot parse %s: %s\n", crash_notes,
						strerror(errno));
		}

		*addr = x86__pa(vaddr + (cpu * MAX_NOTE_BYTES));
		*len = MAX_NOTE_BYTES;

		dbgprintf("crash_notes addr = %Lx\n",
			  (unsigned long long)*addr);

		fclose(fp);
		return 0;
	} else
		return get_crash_notes_per_cpu(cpu, addr, len);
}

static enum coretype get_core_type(struct crash_elf_info *elf_info,
				   struct memory_range *range, int ranges)
{
	if ((elf_info->machine) == EM_X86_64)
		return CORE_TYPE_ELF64;
	else {
		/* fall back to default */
		if (ranges == 0)
			return CORE_TYPE_ELF64;

		if (range[ranges - 1].end > 0xFFFFFFFFUL)
			return CORE_TYPE_ELF64;
		else
			return CORE_TYPE_ELF32;
	}
}

/* Appends memmap=X#Y commandline for ACPI to command line*/
static int cmdline_add_memmap_acpi(char *cmdline, unsigned long start,
					unsigned long end)
{
	int align = 1024;
	unsigned long startk, endk;

	if (!(end - start))
		return 0;

	startk = start/1024;
	endk = (end + align - 1)/1024;
	cmdline_add_memmap_internal(cmdline, startk, endk, RANGE_ACPI);

	dbgprintf("Command line after adding acpi memmap\n");
	dbgprintf("%s\n", cmdline);

	return 0;
}

/* Appends 'acpi_rsdp=' commandline for efi boot crash dump */
static void cmdline_add_efi(char *cmdline)
{
	FILE *fp;
	int cmdlen, len;
	char line[MAX_LINE], *s;
	const char *acpis = " acpi_rsdp=";

	fp = fopen("/sys/firmware/efi/systab", "r");
	if (!fp)
		return;

	while(fgets(line, sizeof(line), fp) != 0) {
		/* ACPI20= always goes before ACPI= */
		if ((strstr(line, "ACPI20=")) || (strstr(line, "ACPI="))) {
		        line[strlen(line) - 1] = '\0';
			s = strchr(line, '=');
			s += 1;
			len = strlen(s) + strlen(acpis);
			cmdlen = strlen(cmdline) + len;
			if (cmdlen > (COMMAND_LINE_SIZE - 1))
				die("Command line overflow\n");
			strcat(cmdline, acpis);
			strcat(cmdline, s);
			dbgprintf("Command line after adding efi\n");
			dbgprintf("%s\n", cmdline);

			break;
		}
	}

	fclose(fp);
}

static void get_backup_area(struct kexec_info *info,
				struct memory_range *range, int ranges)
{
	int i;

	/* Look for first 640 KiB RAM region. */
	for (i = 0; i < ranges; ++i) {
		if (range[i].type != RANGE_RAM || range[i].end > 0xa0000)
			continue;

		info->backup_src_start = range[i].start;
		info->backup_src_size = range[i].end - range[i].start + 1;

		dbgprintf("%s: %016llx-%016llx : System RAM\n", __func__,
						range[i].start, range[i].end);

		return;
	}

	/* First 640 KiB RAM region not found. Assume defaults. */
	info->backup_src_start = BACKUP_SRC_START;
	info->backup_src_size = BACKUP_SRC_END - BACKUP_SRC_START + 1;
}

/* Appends memmap=X$Y commandline for reserved memory to command line*/
static int cmdline_add_memmap_reserved(char *cmdline, unsigned long start,
					unsigned long end)
{
	int align = 1024;
	unsigned long startk, endk;

	if (!(end - start))
		return 0;

	startk = start/1024;
	endk = (end + align - 1)/1024;
	cmdline_add_memmap_internal(cmdline, startk, endk, RANGE_RESERVED);

#ifdef DEBUG
		printf("Command line after adding reserved memmap\n");
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
	unsigned long sz, bufsz, memsz, elfcorehdr;
	int nr_ranges = 0, align = 1024, i;
	struct memory_range *mem_range, *memmap_p;
	struct crash_elf_info elf_info;
	unsigned kexec_arch;

	memset(&elf_info, 0x0, sizeof(elf_info));

	/* Constant parts of the elf_info */
	memset(&elf_info, 0, sizeof(elf_info));
	elf_info.data             = ELFDATA2LSB;

	/* Get the architecture of the running kernel */
	kexec_arch = info->kexec_flags & KEXEC_ARCH_MASK;
	if (kexec_arch == KEXEC_ARCH_DEFAULT)
		kexec_arch = KEXEC_ARCH_NATIVE;
	
        /* Get the elf architecture of the running kernel */
	switch(kexec_arch) {
	case KEXEC_ARCH_X86_64:
		elf_info.machine = EM_X86_64;
		break;
	case KEXEC_ARCH_386:
		elf_info.machine       = EM_386;
		elf_info.lowmem_limit  = X86_MAXMEM;
		elf_info.get_note_info = get_crash_notes;
		break;
	default:
		fprintf(stderr, "unsupported crashdump architecture: %04x\n",
			kexec_arch);
		return -1;
	}

	if (xen_present()) {
		if (get_crash_memory_ranges_xen(&mem_range, &nr_ranges,
						elf_info.lowmem_limit) < 0)
			return -1;
	} else
		if (get_crash_memory_ranges(&mem_range, &nr_ranges,
						info->kexec_flags,
						elf_info.lowmem_limit) < 0)
			return -1;

	get_backup_area(info, mem_range, nr_ranges);

	dbgprintf("CRASH MEMORY RANGES\n");

	for(i = 0; i < nr_ranges; ++i)
		dbgprintf("%016Lx-%016Lx\n", mem_range[i].start, mem_range[i].end);

	/*
	 * if the core type has not been set on command line, set it here
	 * automatically
	 */
	if (arch_options.core_header_type == CORE_TYPE_UNDEF) {
		arch_options.core_header_type =
			get_core_type(&elf_info, mem_range, nr_ranges);
	}
	/* Get the elf class... */
	elf_info.class = ELFCLASS32;
	if (arch_options.core_header_type == CORE_TYPE_ELF64) {
		elf_info.class = ELFCLASS64;
	}

	if (get_kernel_page_offset(info, &elf_info))
		return -1;

	if (get_kernel_paddr(info, &elf_info))
		return -1;

	if (get_kernel_vaddr_and_size(info, &elf_info))
		return -1;

	/* Memory regions which panic kernel can safely use to boot into */
	sz = (sizeof(struct memory_range) * CRASH_MAX_MEMMAP_NR);
	memmap_p = xmalloc(sz);
	memset(memmap_p, 0, sz);
	add_memmap(memmap_p, info->backup_src_start, info->backup_src_size);
	sz = crash_reserved_mem.end - crash_reserved_mem.start +1;
	if (add_memmap(memmap_p, crash_reserved_mem.start, sz) < 0) {
		return ENOCRASHKERNEL;
	}

	if (crash_reserved_low_mem.start) {
		sz = crash_reserved_low_mem.end - crash_reserved_low_mem.start
					 +1;
		add_memmap(memmap_p, crash_reserved_low_mem.start, sz);
	}

	/* Create a backup region segment to store backup data*/
	if (!(info->kexec_flags & KEXEC_PRESERVE_CONTEXT)) {
		sz = _ALIGN(info->backup_src_size, align);
		tmp = xmalloc(sz);
		memset(tmp, 0, sz);
		info->backup_start = add_buffer(info, tmp, sz, sz, align,
						0, max_addr, -1);
		dbgprintf("Created backup segment at 0x%lx\n",
			  info->backup_start);
		if (delete_memmap(memmap_p, info->backup_start, sz) < 0)
			return EFAILED;
	}

	/* Create elf header segment and store crash image data. */
	if (arch_options.core_header_type == CORE_TYPE_ELF64) {
		if (crash_create_elf64_headers(info, &elf_info, mem_range,
						nr_ranges, &tmp, &bufsz,
						ELF_CORE_HEADER_ALIGN) < 0)
			return EFAILED;
	}
	else {
		if (crash_create_elf32_headers(info, &elf_info, mem_range,
						nr_ranges, &tmp, &bufsz,
						ELF_CORE_HEADER_ALIGN) < 0)
			return EFAILED;
	}
	/* the size of the elf headers allocated is returned in 'bufsz' */

	/* Hack: With some ld versions (GNU ld version 2.14.90.0.4 20030523),
	 * vmlinux program headers show a gap of two pages between bss segment
	 * and data segment but effectively kernel considers it as bss segment
	 * and overwrites the any data placed there. Hence bloat the memsz of
	 * elf core header segment to 16K to avoid being placed in such gaps.
	 * This is a makeshift solution until it is fixed in kernel.
	 */
	if (bufsz < (16*1024)) {
		/* bufsize is big enough for all the PT_NOTE's and PT_LOAD's */
		memsz = 16*1024;
		/* memsz will be the size of the memory hole we look for */
	} else {
		memsz = bufsz;
	}
	elfcorehdr = add_buffer(info, tmp, bufsz, memsz, align, min_base,
							max_addr, -1);
	dbgprintf("Created elf header segment at 0x%lx\n", elfcorehdr);
	if (delete_memmap(memmap_p, elfcorehdr, memsz) < 0)
		return -1;
	cmdline_add_memmap(mod_cmdline, memmap_p);
	cmdline_add_efi(mod_cmdline);
	cmdline_add_elfcorehdr(mod_cmdline, elfcorehdr);

	/* Inform second kernel about the presence of ACPI tables. */
	for (i = 0; i < CRASH_MAX_MEMORY_RANGES; i++) {
		unsigned long start, end;
		if ( !( mem_range[i].type == RANGE_ACPI
			|| mem_range[i].type == RANGE_ACPI_NVS
			|| mem_range[i].type == RANGE_RESERVED) )
			continue;
		start = mem_range[i].start;
		end = mem_range[i].end;
		if (mem_range[i].type == RANGE_RESERVED)
			cmdline_add_memmap_reserved(mod_cmdline, start, end);
		else
			cmdline_add_memmap_acpi(mod_cmdline, start, end);
	}
	return 0;
}

int is_crashkernel_mem_reserved(void)
{
	uint64_t start, end;

	if (parse_iomem_single("Crash kernel\n", &start, &end) || start == end)
		return 0;

	crash_reserved_mem.start = start;
	crash_reserved_mem.end = end;
	crash_reserved_mem.type = RANGE_RAM;

	/* If there is no Crash low kernel, still can go on */
	if (parse_iomem_single("Crash kernel low\n", &start, &end) ||
					start == end)
		return 1;

	crash_reserved_low_mem.start = start;
	crash_reserved_low_mem.end = end;
	crash_reserved_low_mem.type = RANGE_RAM;

	return 1;
}
