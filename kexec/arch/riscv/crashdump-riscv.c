#include <errno.h>
#include <linux/elf.h>
#include <unistd.h>

#include "kexec.h"
#include "crashdump.h"
#include "kexec-elf.h"
#include "mem_regions.h"

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
struct memory_range elfcorehdr_mem = {0};

static unsigned long long get_page_offset(struct kexec_info *info)
{
	unsigned long long vaddr_off = 0;
	unsigned long long page_size = sysconf(_SC_PAGESIZE);
	unsigned long long init_start = get_kernel_sym("_sinittext");

	/*
	 * Begining of init section is aligned to page size
	 */
	vaddr_off = init_start - page_size;

	return vaddr_off;
}

int load_elfcorehdr(struct kexec_info *info)
{
	struct memory_range crashkern_range = {0};
	struct memory_range *ranges = NULL;
	unsigned long start = 0;
	unsigned long end = 0;
	unsigned long buf_size = 0;
	unsigned long elfcorehdr_addr = 0;
	void* buf = NULL;
	int i = 0;
	int ret = 0;

	ret = parse_iomem_single("Kernel code\n", &start, NULL);
	if (ret) {
		fprintf(stderr, "Cannot determine kernel physical base addr\n");
		return -EINVAL;
	}
	elf_info.kern_paddr_start = start;

	ret = parse_iomem_single("Kernel bss\n", NULL, &end);
	if (ret) {
		fprintf(stderr, "Cannot determine kernel physical bss addr\n");
		return -EINVAL;
	}
	elf_info.kern_paddr_start = start;
	elf_info.kern_size = end - start;

	elf_info.kern_vaddr_start = get_kernel_sym("_text");
	if (!elf_info.kern_vaddr_start) {
		elf_info.kern_vaddr_start = UINT64_MAX;
	}

	elf_info.page_offset = get_page_offset(info);
	dbgprintf("page_offset:   %016llx\n", elf_info.page_offset);

	ret = parse_iomem_single("Crash kernel\n", &start, &end);
	if (ret) {
		fprintf(stderr, "Cannot determine kernel physical bss addr\n");
		return -EINVAL;
	}
	crashkern_range.start = start;
	crashkern_range.end = end;
	crashkern_range.type = RANGE_RESERVED;

	ranges = info->memory_range;
	for (i = 0; i < info->memory_ranges; i++) {
		ret = mem_regions_alloc_and_add(&crash_mem_ranges,
						ranges[i].start,
						ranges[i].end - ranges[i].start + 1,
						ranges[i].type);
		if (ret ) {
			fprintf(stderr, "Could not create crash_mem_ranges\n");
			return ret;
		}
	}

	ret = mem_regions_alloc_and_exclude(&crash_mem_ranges,
					    &crashkern_range);
	if (ret) {
		fprintf(stderr, "Could not exclude crashkern_range\n");
		return ret;
	}

#if __riscv_xlen == 64
	crash_create_elf64_headers(info, &elf_info, crash_mem_ranges.ranges,
				   crash_mem_ranges.size, &buf, &buf_size,
				   ELF_CORE_HEADER_ALIGN);

#else
	crash_create_elf32_headers(info, &elf_info, crash_mem_ranges.ranges,
				   crash_mem_ranges.size, &buf, &buf_size,
				   ELF_CORE_HEADER_ALIGN);
#endif


	elfcorehdr_addr = add_buffer_phys_virt(info, buf, buf_size,
					       buf_size, 0,
					       crashkern_range.start,
					       crashkern_range.end,
					       -1, 0);

	elfcorehdr_mem.start = elfcorehdr_addr;
	elfcorehdr_mem.end = elfcorehdr_addr + buf_size - 1;

	dbgprintf("%s: elfcorehdr 0x%llx-0x%llx\n", __func__,
		  elfcorehdr_mem.start, elfcorehdr_mem.end);

	return 0;
}

int is_crashkernel_mem_reserved(void)
{
	uint64_t start = 0;
	uint64_t end = 0;

	return parse_iomem_single("Crash kernel\n", &start, &end) == 0 ?
	       (start != end) : 0;
}

int get_crash_kernel_load_range(uint64_t *start, uint64_t *end)
{
	return parse_iomem_single("Crash kernel\n", start, end);
}

