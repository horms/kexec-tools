/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 FORTH-ICS/CARV
 *              Nick Kossifidis <mick@ics.forth.gr>
 */

#include "kexec-syscall.h"	/* For KEXEC_ARCH_RISCV */
#include "kexec.h"		/* For OPT_MAX and concat_cmdline() */
#include "mem_regions.h"	/* For mem_regions_sort() */
#include "dt-ops.h"		/* For dtb_set_bootargs() */
#include <arch/options.h>	/* For KEXEC_ARCH_OPTIONS */
#include <getopt.h>		/* For struct option */
#include <sys/stat.h>		/* For stat() and struct stat */
#include <stdlib.h>		/* For free() */
#include <errno.h>		/* For EINVAL */
#include <libfdt.h>		/* For DeviceTree handling */
#include "kexec-riscv.h"
#include "iomem.h"
#include <stdbool.h>

const struct arch_map_entry arches[] = {
	{ "riscv32", KEXEC_ARCH_RISCV },
	{ "riscv64", KEXEC_ARCH_RISCV },
	{ NULL, 0 },
};


struct file_type file_type[] = {
	{"elf-riscv", elf_riscv_probe, elf_riscv_load, elf_riscv_usage},
};
int file_types = sizeof(file_type) / sizeof(file_type[0]);

static const char riscv_opts_usage[] =
"	--append=STRING		Append STRING to the kernel command line.\n"
"	--dtb=FILE		Use FILE as the device tree blob.\n"
"	--initrd=FILE		Use FILE as the kernel initial ramdisk.\n"
"	--command-line=STRING	Use STRING as the kernel's command line.\n"
"	--reuse-cmdline		Use kernel command line from running system.\n";

static struct riscv_opts arch_options = {0};
static struct fdt_image provided_fdt = {0};

/****************\
* COMMON HELPERS *
\****************/

int load_extra_segments(struct kexec_info *info, uint64_t kernel_base,
			uint64_t kernel_size, uint64_t max_addr)
{
	struct fdt_image *fdt = arch_options.fdt;
	char *initrd_buf = NULL;
	off_t initrd_size = 0;
	uint64_t initrd_base = 0;
	uint64_t start = 0;
	uint64_t end = 0;
	uint64_t min_usable = kernel_base + kernel_size;
	uint64_t max_usable = max_addr;
	int ret = 0;

	/* Prepare the device tree */
	if (info->kexec_flags & KEXEC_ON_CRASH) {
		ret = load_elfcorehdr(info);
		if (ret) {
			fprintf(stderr, "Couldn't create elfcorehdr\n");
			return ret;
		}

		ret = dtb_add_range_property(&fdt->buf, &fdt->size,
					     elfcorehdr_mem.start, elfcorehdr_mem.end,
					     "chosen", "linux,elfcorehdr");
		if (ret) {
			fprintf(stderr, "Couldn't add elfcorehdr to fdt\n");
			return ret;
		}

		ret = get_crash_kernel_load_range(&start, &end);
		if (ret) {
			fprintf(stderr, "Couldn't get crashkenel region\n");
			return ret;
		}

		ret = dtb_add_range_property(&fdt->buf, &fdt->size, start, end,
					     "chosen", "linux,usable-memory-range");
		if (ret) {
			fprintf(stderr, "Couldn't add usable-memory-range to fdt\n");
			return ret;
		}

		max_usable = end;
	} else {
		/*
		 * Make sure we remove elfcorehdr and usable-memory-range
		 * when switching from crash kernel to a normal one.
		 */
		dtb_delete_property(fdt->buf, "chosen", "linux,elfcorehdr");
		dtb_delete_property(fdt->buf, "chosen", "linux,usable-memory-range");
	}

	/* Do we need to include an initrd image ? */
	if (!arch_options.initrd_path && !arch_options.initrd_end)
		dtb_clear_initrd(&fdt->buf, &fdt->size);
	else if (arch_options.initrd_path) {
		if (arch_options.initrd_end)
			fprintf(stderr, "Warning: An initrd image was provided"
					", will ignore reuseinitrd\n");

		initrd_buf = slurp_file(arch_options.initrd_path,
					&initrd_size);
		if (!initrd_buf) {
			fprintf(stderr, "Couldn't read provided initrd\n");
			return -EINVAL;
		}

		initrd_base = add_buffer_phys_virt(info, initrd_buf,
						   initrd_size,
						   initrd_size, 0,
						   min_usable,
						   max_usable, -1, 0);

		dtb_set_initrd(&fdt->buf, &fdt->size, initrd_base,
			       initrd_base + initrd_size);

		dbgprintf("Base addr for initrd image: 0x%lX\n", initrd_base);
		max_usable = initrd_base;
	}

	/* Add device tree */
	add_buffer_phys_virt(info, fdt->buf, fdt->size, fdt->size, 0,
			     min_usable, max_usable, -1, 0);

	return 0;
}


/**************\
* ENTRY POINTS *
\**************/

void arch_usage(void)
{
	printf(riscv_opts_usage);
}

int arch_process_options(int argc, char **argv)
{
	static const struct option options[] = {
		KEXEC_ARCH_OPTIONS
		{ 0 },
	};
	static const char short_options[] = KEXEC_ARCH_OPT_STR;
	struct stat st = {0};
	char *append = NULL;
	char *cmdline = NULL;
	void *tmp = NULL;
	off_t tmp_size = 0;
	int opt = 0;
	int ret = 0;

	while ((opt = getopt_long(argc, argv, short_options,
				  options, 0)) != -1) {
		switch (opt) {
		case OPT_APPEND:
			append = optarg;
			break;
		case OPT_CMDLINE:
			if (cmdline)
				fprintf(stderr,
					"Warning: Kernel's cmdline "
					"set twice !\n");
			cmdline = optarg;
			break;
		case OPT_REUSE_CMDLINE:
			if (cmdline)
				fprintf(stderr,
					"Warning: Kernel's cmdline "
					"set twice !\n");
			cmdline = get_command_line();
			break;
		case OPT_DTB:
			ret = stat(optarg, &st);
			if (ret) {
				fprintf(stderr,
					"Could not find the provided dtb !\n");
				return -EINVAL;
			}
			arch_options.fdt_path = optarg;
			break;
		case OPT_INITRD:
			ret = stat(optarg, &st);
			if (ret) {
				fprintf(stderr,
					"Could not find the provided "
					"initrd image !\n");
				return -EINVAL;
			}
			arch_options.initrd_path = optarg;
			break;
		default:
			break;
		}
	}

	/* Handle Kernel's command line */
	if (append && !cmdline)
		fprintf(stderr, "Warning: No cmdline provided, "
				"using append string as cmdline\n");
	if (!append && !cmdline)
		fprintf(stderr, "Warning: No cmdline or append string "
				"provided\n");

	if (append || cmdline)
		/*
		 * Note that this also handles the case where "cmdline"
		 * or "append" is NULL.
		 */
		arch_options.cmdline = concat_cmdline(cmdline, append);

	/* Handle FDT image */
	if (!arch_options.fdt_path) {
		ret = stat("/sys/firmware/fdt", &st);
		if (ret) {
			fprintf(stderr, "No dtb provided and "
					"/sys/firmware/fdt is not present\n");
			return -EINVAL;
		}
		fprintf(stderr, "Warning: No dtb provided, "
				"using /sys/firmware/fdt\n");
		arch_options.fdt_path = "/sys/firmware/fdt";
	}

	tmp = slurp_file(arch_options.fdt_path, &tmp_size);
	if (!tmp) {
		fprintf(stderr, "Couldn't read provided fdt\n");
		return -EINVAL;
	}

	ret = fdt_check_header(tmp);
	if (ret) {
		fprintf(stderr, "Got an ivalid fdt image !\n");
		free(tmp);
		return -EINVAL;
	}
	provided_fdt.buf = tmp;
	provided_fdt.size = tmp_size;

	if (arch_options.cmdline) {
		ret = dtb_set_bootargs(&provided_fdt.buf, &provided_fdt.size,
				       arch_options.cmdline);
		if (ret < 0) {
			fprintf(stderr, "Could not set bootargs on "
					"the fdt image\n");
			return ret;
		}
	}

	arch_options.fdt = &provided_fdt;

	return 0;
}

/*
 * This one is called after arch_process_options so we already
 * have an fdt image in place.
 */
void arch_reuse_initrd(void)
{
	const uint32_t *prop32 = NULL;
	uint32_t addr_cells = 0;
	const void *prop = 0;
	int prop_size = 0;
	uint64_t initrd_start = 0;
	uint64_t initrd_end = 0;
	int chosen_offset = 0;
	struct fdt_image *fdt = &provided_fdt;

	chosen_offset = fdt_subnode_offset(fdt->buf, 0, "chosen");
	if (chosen_offset < 0) {
		fprintf(stderr, "No /chosen node found on fdt image "
				"unable to reuse initrd\n");
		return;
	}

	prop32 = fdt_getprop(fdt->buf, 0, "#address-cells", NULL);
	if (!prop32) {
		fprintf(stderr, "No #address-cells property on root node\n");
		return;
	}
	addr_cells = be32_to_cpu(*prop32);

	prop = fdt_getprop(fdt->buf, chosen_offset,
			   "linux,initrd-start", &prop_size);
	if (!prop) {
		fprintf(stderr, "Could not get linux,initrd-start\n");
		return;
	}
	dtb_extract_int_property(&initrd_start, prop, addr_cells);

	prop = fdt_getprop(fdt->buf, chosen_offset,
			   "linux,initrd-end", &prop_size);
	if (!prop) {
		fprintf(stderr, "Could not get linux,initrd-end\n");
		return;
	}
	dtb_extract_int_property(&initrd_end, prop, addr_cells);

	arch_options.initrd_start = initrd_start;
	arch_options.initrd_end = initrd_end;
	dbgprintf("initrd_start: 0x%lX, initrd_end: 0x%lX\n",
		  initrd_start, initrd_end);

}

static bool to_be_excluded(char *str, unsigned long long start, unsigned long long end)
{
	if (!strncmp(str, CRASH_KERNEL, strlen(CRASH_KERNEL))) {
		uint64_t load_start, load_end;

		if (!get_crash_kernel_load_range(&load_start, &load_end) &&
		    (load_start == start) && (load_end == end))
			return false;

		return true;
	}

	if (!strncmp(str, SYSTEM_RAM, strlen(SYSTEM_RAM)) ||
	    !strncmp(str, KERNEL_CODE, strlen(KERNEL_CODE)) ||
	    !strncmp(str, KERNEL_DATA, strlen(KERNEL_DATA)))
		return false;
	else
		return true;
}

int get_memory_ranges(struct memory_range **range, int *num_ranges,
		      unsigned long kexec_flags)
{
	struct memory_ranges sysmem_ranges = {0};
	const char *iomem = proc_iomem();
	struct memory_range excl_range;
	unsigned long long start, end;
	int consumed, count, ret = 0;
	FILE *fp = NULL, *sp = NULL;
	char line[MAX_LINE], *str;

	fp = fopen(iomem, "r");
	if (!fp) {
		fprintf(stderr, "Cannot open %s: %s\n", iomem, strerror(errno));
		return -1;
	}

	sp = fopen(iomem, "r");
	if (!sp) {
		fprintf(stderr, "Cannot open %s: %s\n", iomem, strerror(errno));
		ret = -1;
		goto err;
	}

	/*
	 * Perform two passes: First add all System RAM, and then
	 * exclude the "Reserved" ranges"
	 */
	while (fgets(line, sizeof(line), fp) != 0) {
		count = sscanf(line, "%llx-%llx : %n", &start, &end, &consumed);
		if (count != 2)
			continue;
		str = line + consumed;

		if (!strncmp(str, SYSTEM_RAM, strlen(SYSTEM_RAM))) {
			ret = mem_regions_alloc_and_add(&sysmem_ranges,
					start, end - start + 1, RANGE_RAM);
			if (ret) {
				fprintf(stderr,
					"Cannot allocate memory for ranges\n");
				ret = -ENOMEM;
				goto err;
			}

		}
	}

	while (fgets(line, sizeof(line), sp) != 0) {
		count = sscanf(line, "%llx-%llx : %n", &start, &end, &consumed);
		if (count != 2)
			continue;
		str = line + consumed;

		if (to_be_excluded(str, start, end)) {
			excl_range.start = start;
			excl_range.end = end;

			ret = mem_regions_alloc_and_exclude(&sysmem_ranges, &excl_range);
			if (ret) {
				fprintf(stderr,
					"Cannot allocate memory for ranges (exclude)\n");
				ret = -ENOMEM;
				goto err;
			}
		}
	}

	*range = sysmem_ranges.ranges;
	*num_ranges = sysmem_ranges.size;

	dbgprint_mem_range("System RAM ranges;",
				sysmem_ranges.ranges, sysmem_ranges.size);

	ret = 0;
 err:
	if (fp)
		fclose(fp);
	if (sp)
		fclose(sp);
	return ret;
}

/*******\
* STUBS *
\*******/

int arch_compat_trampoline(struct kexec_info *UNUSED(info))
{
	return 0;
}

void arch_update_purgatory(struct kexec_info *UNUSED(info))
{
}

int arch_do_exclude_segment(struct kexec_info *UNUSED(info), struct kexec_segment *UNUSED(segment))
{
	return 0;
}
