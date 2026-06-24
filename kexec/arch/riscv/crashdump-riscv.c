#include <errno.h>
#include <elf.h>
#include <elf_info.h>
#include <unistd.h>

#include "kexec.h"
#include "crashdump.h"
#include "kexec-elf.h"
#include "mem_regions.h"
#include "iomem.h"

static struct crash_elf_info elf_info = {
#if __riscv_xlen == 64
	.class		= ELFCLASS64,
#else
	.class		= ELFCLASS32,
#endif
	.data		= ELFDATA2LSB,
	.machine	= EM_RISCV,
};

static struct memory_ranges crash_mem_ranges = {0};
static struct memory_ranges system_mem_ranges = {0};
struct memory_range elfcorehdr_mem = {0};

static unsigned long long phys_offset;

static int get_page_offset(unsigned long long *page_offset)
{
	int fd, ret = 0;

	if ((fd = open("/proc/kcore", O_RDONLY)) < 0) {
		fprintf(stderr, "Can't open (%s).\n", "/proc/kcore");
		return EFAILED;
	}

	ret = read_page_offset_elf_kcore(fd, (long *)page_offset);
	if (ret)
		fprintf(stderr, "Can't get page_offset from /proc/kcore\n");

	close(fd);
	return ret;
}

static int get_phys_offset(unsigned long long *phys_offset)
{
	int fd, ret = 0;

	if ((fd = open("/proc/kcore", O_RDONLY)) < 0) {
		fprintf(stderr, "Can't open (%s).\n", "/proc/kcore");
		return EFAILED;
	}

	ret = read_phys_offset_elf_kcore(fd, (long *)phys_offset);
	if (ret)
		fprintf(stderr, "Can't get phys_offset from /proc/kcore\n");

	close(fd);
	return ret;
}

unsigned long phys_to_virt(struct crash_elf_info *elf_info, unsigned long long p)
{
	return elf_info->page_offset - phys_offset + p;
}

/*
 * iomem_range_callback() - callback called for each iomem region
 * @data: not used
 * @nr: not used
 * @str: name of the memory region
 * @base: start address of the memory region
 * @length: size of the memory region
 *
 * This function is called once for each memory region found in /proc/iomem.
 * It locates system RAM and crashkernel reserved memory and places these to
 * variables, respectively, system_memory_rgns and crash_mem_ranges.
 */
static int iomem_range_callback(void *UNUSED(data), int UNUSED(nr),
				char *str, unsigned long long base,
				unsigned long long length)
{
	if (strncmp(str, CRASH_KERNEL, strlen(CRASH_KERNEL)) == 0)
		return mem_regions_alloc_and_add(&crash_mem_ranges,
						base, length, RANGE_RAM);
	else if (strncmp(str, SYSTEM_RAM, strlen(SYSTEM_RAM)) == 0)
		return mem_regions_alloc_and_add(&system_mem_ranges,
						base, length, RANGE_RAM);
	else if (strncmp(str, KERNEL_CODE, strlen(KERNEL_CODE)) == 0)
		elf_info.kern_paddr_start = base;
	else if (strncmp(str, KERNEL_DATA, strlen(KERNEL_DATA)) == 0)
		elf_info.kern_size = base + length - elf_info.kern_paddr_start;

	return 0;
}

/*
 * crash_get_memory_ranges() - read system physical memory
 *
 * Function reads through system physical memory and stores found memory
 * regions in system_memory_ranges.
 * Regions are sorted in ascending order.
 *
 * Returns 0 in case of success and a negative value otherwise.
 */
static int crash_get_memory_ranges(void)
{
	int i;

	if (!crash_mem_ranges.size)
		kexec_iomem_for_each_line(NULL, iomem_range_callback, NULL);

	if (!crash_mem_ranges.size)
		return -EINVAL;

	dbgprint_mem_range("Reserved memory range",
			crash_mem_ranges.ranges, crash_mem_ranges.size);

	for (i = 0; i < crash_mem_ranges.size; i++) {
		if (mem_regions_alloc_and_exclude(&system_mem_ranges,
					&crash_mem_ranges.ranges[i])) {
			fprintf(stderr, "Cannot allocate memory for ranges\n");
			return -ENOMEM;
		}
	}

	/*
	 * Make sure that the memory regions are sorted.
	 */
	mem_regions_sort(&system_mem_ranges);

	dbgprint_mem_range("Coredump memory ranges",
			   system_mem_ranges.ranges, system_mem_ranges.size);

	/*
	 * For additional kernel code/data segment.
	 * kern_paddr_start/kern_size are determined in iomem_range_callback
	 */
	elf_info.kern_vaddr_start = get_kernel_sym("_text");
	if (!elf_info.kern_vaddr_start)
		elf_info.kern_vaddr_start = UINT64_MAX;

	return 0;
}

int load_elfcorehdr(struct kexec_info *info)
{
	unsigned long buf_size = 0;
	unsigned long elfcorehdr_addr = 0;
	void* buf = NULL;

	if (crash_get_memory_ranges())
		return EFAILED;

	if (get_phys_offset(&phys_offset))
		return EFAILED;

	dbgprintf("phys_offset:   %016llx\n", phys_offset);

	if (get_page_offset(&elf_info.page_offset))
		return EFAILED;

	dbgprintf("page_offset:   %016llx\n", elf_info.page_offset);

#if __riscv_xlen == 64
	crash_create_elf64_headers(info, &elf_info, system_mem_ranges.ranges,
				   system_mem_ranges.size, &buf, &buf_size,
				   ELF_CORE_HEADER_ALIGN);

#else
	crash_create_elf32_headers(info, &elf_info, system_mem_ranges.ranges,
				   system_mem_ranges.size, &buf, &buf_size,
				   ELF_CORE_HEADER_ALIGN);
#endif


	elfcorehdr_addr = add_buffer_phys_virt(info, buf, buf_size,
					    buf_size, 0,
					    crash_mem_ranges.ranges[crash_mem_ranges.size - 1].start,
					    crash_mem_ranges.ranges[crash_mem_ranges.size - 1].end,
					    -1, 0);

	elfcorehdr_mem.start = elfcorehdr_addr;
	elfcorehdr_mem.end = elfcorehdr_addr + buf_size - 1;

	dbgprintf("%s: elfcorehdr 0x%llx-0x%llx\n", __func__,
		  elfcorehdr_mem.start, elfcorehdr_mem.end);

	return 0;
}

int is_crashkernel_mem_reserved(void)
{
	if (!crash_mem_ranges.size)
		kexec_iomem_for_each_line(NULL, iomem_range_callback, NULL);

	return crash_mem_ranges.size;
}

int get_crash_kernel_load_range(uint64_t *start, uint64_t *end)
{
	if (!crash_mem_ranges.size)
		kexec_iomem_for_each_line(NULL, iomem_range_callback, NULL);

	if (!crash_mem_ranges.size)
		return -1;

	*start = crash_mem_ranges.ranges[crash_mem_ranges.size - 1].start;
	*end = crash_mem_ranges.ranges[crash_mem_ranges.size - 1].end;

	return 0;
}
