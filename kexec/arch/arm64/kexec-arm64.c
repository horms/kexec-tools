/*
 * ARM64 kexec.
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <libfdt.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <linux/elf-em.h>
#include <elf.h>

#include "kexec.h"
#include "kexec-arm64.h"
#include "crashdump.h"
#include "crashdump-arm64.h"
#include "dt-ops.h"
#include "fs2dt.h"
#include "iomem.h"
#include "kexec-syscall.h"
#include "arch/options.h"

/* Global varables the core kexec routines expect. */

unsigned char reuse_initrd;

off_t initrd_base;
off_t initrd_size;

const struct arch_map_entry arches[] = {
	{ "aarch64", KEXEC_ARCH_ARM64 },
	{ "aarch64_be", KEXEC_ARCH_ARM64 },
	{ NULL, 0 },
};

struct file_type file_type[] = {
	{"vmlinux", elf_arm64_probe, elf_arm64_load, elf_arm64_usage},
	{"Image", image_arm64_probe, image_arm64_load, image_arm64_usage},
	{"uImage", uImage_arm64_probe, uImage_arm64_load, uImage_arm64_usage},
};

int file_types = sizeof(file_type) / sizeof(file_type[0]);

/* arm64 global varables. */

struct arm64_opts arm64_opts;
struct arm64_mem arm64_mem = {
	.phys_offset = arm64_mem_ngv,
	.vp_offset = arm64_mem_ngv,
};

uint64_t get_phys_offset(void)
{
	assert(arm64_mem.phys_offset != arm64_mem_ngv);
	return arm64_mem.phys_offset;
}

uint64_t get_vp_offset(void)
{
	assert(arm64_mem.vp_offset != arm64_mem_ngv);
	return arm64_mem.vp_offset;
}

/**
 * arm64_process_image_header - Process the arm64 image header.
 *
 * Make a guess that KERNEL_IMAGE_SIZE will be enough for older kernels.
 */

int arm64_process_image_header(const struct arm64_image_header *h)
{
#if !defined(KERNEL_IMAGE_SIZE)
# define KERNEL_IMAGE_SIZE MiB(16)
#endif

	if (!arm64_header_check_magic(h))
		return EFAILED;

	if (h->image_size) {
		arm64_mem.text_offset = arm64_header_text_offset(h);
		arm64_mem.image_size = arm64_header_image_size(h);
	} else {
		/* For 3.16 and older kernels. */
		arm64_mem.text_offset = 0x80000;
		arm64_mem.image_size = KERNEL_IMAGE_SIZE;
		fprintf(stderr,
			"kexec: %s: Warning: Kernel image size set to %lu MiB.\n"
			"  Please verify compatability with lodaed kernel.\n",
			__func__, KERNEL_IMAGE_SIZE / 1024UL / 1024UL);
	}

	return 0;
}

void arch_usage(void)
{
	printf(arm64_opts_usage);
}

int arch_process_options(int argc, char **argv)
{
	static const char short_options[] = KEXEC_OPT_STR "";
	static const struct option options[] = {
		KEXEC_ARCH_OPTIONS
		{ 0 }
	};
	int opt;
	char *cmdline = NULL;
	const char *append = NULL;

	for (opt = 0; opt != -1; ) {
		opt = getopt_long(argc, argv, short_options, options, 0);

		switch (opt) {
		case OPT_APPEND:
			append = optarg;
			break;
		case OPT_REUSE_CMDLINE:
			cmdline = get_command_line();
			break;
		case OPT_DTB:
			arm64_opts.dtb = optarg;
			break;
		case OPT_INITRD:
			arm64_opts.initrd = optarg;
			break;
		case OPT_PANIC:
			die("load-panic (-p) not supported");
			break;
		default:
			break; /* Ignore core and unknown options. */
		}
	}

	arm64_opts.command_line = concat_cmdline(cmdline, append);

	dbgprintf("%s:%d: command_line: %s\n", __func__, __LINE__,
		arm64_opts.command_line);
	dbgprintf("%s:%d: initrd: %s\n", __func__, __LINE__,
		arm64_opts.initrd);
	dbgprintf("%s:%d: dtb: %s\n", __func__, __LINE__, arm64_opts.dtb);

	return 0;
}

/**
 * struct dtb - Info about a binary device tree.
 *
 * @buf: Device tree data.
 * @size: Device tree data size.
 * @name: Shorthand name of this dtb for messages.
 * @path: Filesystem path.
 */

struct dtb {
	char *buf;
	off_t size;
	const char *name;
	const char *path;
};

/**
 * dump_reservemap - Dump the dtb's reservemap.
 */

static void dump_reservemap(const struct dtb *dtb)
{
	int i;

	for (i = 0; ; i++) {
		uint64_t address;
		uint64_t size;

		fdt_get_mem_rsv(dtb->buf, i, &address, &size);

		if (!size)
			break;

		dbgprintf("%s: %s {%" PRIx64 ", %" PRIx64 "}\n", __func__,
			dtb->name, address, size);
	}
}

/**
 * set_bootargs - Set the dtb's bootargs.
 */

static int set_bootargs(struct dtb *dtb, const char *command_line)
{
	int result;

	if (!command_line || !command_line[0])
		return 0;

	result = dtb_set_bootargs(&dtb->buf, &dtb->size, command_line);

	if (result) {
		fprintf(stderr,
			"kexec: Set device tree bootargs failed.\n");
		return EFAILED;
	}

	return 0;
}

/**
 * read_proc_dtb - Read /proc/device-tree.
 */

static int read_proc_dtb(struct dtb *dtb)
{
	int result;
	struct stat s;
	static const char path[] = "/proc/device-tree";

	result = stat(path, &s);

	if (result) {
		dbgprintf("%s: %s\n", __func__, strerror(errno));
		return EFAILED;
	}

	dtb->path = path;
	create_flatten_tree((char **)&dtb->buf, &dtb->size, NULL);

	return 0;
}

/**
 * read_sys_dtb - Read /sys/firmware/fdt.
 */

static int read_sys_dtb(struct dtb *dtb)
{
	int result;
	struct stat s;
	static const char path[] = "/sys/firmware/fdt";

	result = stat(path, &s);

	if (result) {
		dbgprintf("%s: %s\n", __func__, strerror(errno));
		return EFAILED;
	}

	dtb->path = path;
	dtb->buf = slurp_file(path, &dtb->size);

	return 0;
}

/**
 * read_1st_dtb - Read the 1st stage kernel's dtb.
 */

static int read_1st_dtb(struct dtb *dtb)
{
	int result;

	dtb->name = "dtb_sys";
	result = read_sys_dtb(dtb);

	if (!result)
		goto on_success;

	dtb->name = "dtb_proc";
	result = read_proc_dtb(dtb);

	if (!result)
		goto on_success;

	dbgprintf("%s: not found\n", __func__);
	return EFAILED;

on_success:
	dbgprintf("%s: found %s\n", __func__, dtb->path);
	return 0;
}

/**
 * setup_2nd_dtb - Setup the 2nd stage kernel's dtb.
 */

static int setup_2nd_dtb(struct dtb *dtb, char *command_line)
{
	int result;

	result = fdt_check_header(dtb->buf);

	if (result) {
		fprintf(stderr, "kexec: Invalid 2nd device tree.\n");
		return EFAILED;
	}

	result = set_bootargs(dtb, command_line);

	dump_reservemap(dtb);

	return result;
}

unsigned long arm64_locate_kernel_segment(struct kexec_info *info)
{
	unsigned long hole;

	hole = locate_hole(info,
		arm64_mem.text_offset + arm64_mem.image_size,
		MiB(2), 0, ULONG_MAX, 1);

	if (hole == ULONG_MAX)
		dbgprintf("%s: locate_hole failed\n", __func__);

	return hole;
}

/**
 * arm64_load_other_segments - Prepare the dtb, initrd and purgatory segments.
 */

int arm64_load_other_segments(struct kexec_info *info,
	unsigned long image_base)
{
	int result;
	unsigned long dtb_base;
	unsigned long hole_min;
	unsigned long hole_max;
	unsigned long initrd_end;
	char *initrd_buf = NULL;
	struct dtb dtb;
	char command_line[COMMAND_LINE_SIZE] = "";

	if (arm64_opts.command_line) {
		strncpy(command_line, arm64_opts.command_line,
			sizeof(command_line));
		command_line[sizeof(command_line) - 1] = 0;
	}

	if (arm64_opts.dtb) {
		dtb.name = "dtb_user";
		dtb.buf = slurp_file(arm64_opts.dtb, &dtb.size);
	} else {
		result = read_1st_dtb(&dtb);

		if (result) {
			fprintf(stderr,
				"kexec: Error: No device tree available.\n");
			return EFAILED;
		}
	}

	result = setup_2nd_dtb(&dtb, command_line);

	if (result)
		return EFAILED;

	/* Put the other segments after the image. */

	hole_min = image_base + arm64_mem.image_size;
	hole_max = ULONG_MAX;

	if (arm64_opts.initrd) {
		initrd_buf = slurp_file(arm64_opts.initrd, &initrd_size);

		if (!initrd_buf)
			fprintf(stderr, "kexec: Empty ramdisk file.\n");
		else {
			/* Put the initrd after the kernel. */

			initrd_base = add_buffer_phys_virt(info, initrd_buf,
				initrd_size, initrd_size, 0,
				hole_min, hole_max, 1, 0);

			initrd_end = initrd_base + initrd_size;

			/* Check limits as specified in booting.txt.
			 * The kernel may have as little as 32 GB of address space to map
			 * system memory and both kernel and initrd must be 1GB aligend.
			 */

			if (_ALIGN_UP(initrd_end, GiB(1)) - _ALIGN_DOWN(image_base, GiB(1)) > GiB(32)) {
				fprintf(stderr, "kexec: Error: image + initrd too big.\n");
				return EFAILED;
			}

			dbgprintf("initrd: base %lx, size %lxh (%ld)\n",
				initrd_base, initrd_size, initrd_size);

			result = dtb_set_initrd((char **)&dtb.buf,
				&dtb.size, initrd_base,
				initrd_base + initrd_size);

			if (result)
				return EFAILED;
		}
	}

	/* Check size limit as specified in booting.txt. */

	if (dtb.size > MiB(2)) {
		fprintf(stderr, "kexec: Error: dtb too big.\n");
		return EFAILED;
	}

	dtb_base = add_buffer_phys_virt(info, dtb.buf, dtb.size, dtb.size,
		0, hole_min, hole_max, 1, 0);

	/* dtb_base is valid if we got here. */

	dbgprintf("dtb:    base %lx, size %lxh (%ld)\n", dtb_base, dtb.size,
		dtb.size);

	elf_rel_build_load(info, &info->rhdr, purgatory, purgatory_size,
		hole_min, hole_max, 1, 0);

	info->entry = (void *)elf_rel_get_addr(&info->rhdr, "purgatory_start");

	elf_rel_set_symbol(&info->rhdr, "arm64_kernel_entry", &image_base,
		sizeof(image_base));

	elf_rel_set_symbol(&info->rhdr, "arm64_dtb_addr", &dtb_base,
		sizeof(dtb_base));

	return 0;
}

/**
 * virt_to_phys - For processing elf file values.
 */

unsigned long virt_to_phys(unsigned long v)
{
	unsigned long p;

	p = v - get_vp_offset() + get_phys_offset();

	return p;
}

/**
 * phys_to_virt - For crashdump setup.
 */

unsigned long phys_to_virt(struct crash_elf_info *elf_info,
	unsigned long long p)
{
	unsigned long v;

	v = p - get_phys_offset() + elf_info->page_offset;

	return v;
}

/**
 * add_segment - Use virt_to_phys when loading elf files.
 */

void add_segment(struct kexec_info *info, const void *buf, size_t bufsz,
	unsigned long base, size_t memsz)
{
	add_segment_phys_virt(info, buf, bufsz, base, memsz, 1);
}

/**
 * get_memory_ranges_iomem_cb - Helper for get_memory_ranges_iomem.
 */

static int get_memory_ranges_iomem_cb(void *data, int nr, char *str,
	unsigned long long base, unsigned long long length)
{
	struct memory_range *r;

	if (nr >= KEXEC_SEGMENT_MAX)
		return -1;

	r = (struct memory_range *)data + nr;

	if (!strncmp(str, SYSTEM_RAM, strlen(SYSTEM_RAM)))
		r->type = RANGE_RAM;
	else if (!strncmp(str, IOMEM_RESERVED, strlen(IOMEM_RESERVED)))
		r->type = RANGE_RESERVED;
	else
		return 1;

	r->start = base;
	r->end = base + length - 1;

	set_phys_offset(r->start);

	dbgprintf("%s: %016llx - %016llx : %s", __func__, r->start,
		r->end, str);

	return 0;
}

/**
 * get_memory_ranges_iomem - Try to get the memory ranges from /proc/iomem.
 */

static int get_memory_ranges_iomem(struct memory_range *array,
	unsigned int *count)
{
	*count = kexec_iomem_for_each_line(NULL,
		get_memory_ranges_iomem_cb, array);

	if (!*count) {
		dbgprintf("%s: failed: No RAM found.\n", __func__);
		return EFAILED;
	}

	return 0;
}

/**
 * get_memory_ranges - Try to get the memory ranges some how.
 */

int get_memory_ranges(struct memory_range **range, int *ranges,
	unsigned long kexec_flags)
{
	static struct memory_range array[KEXEC_SEGMENT_MAX];
	unsigned int count;
	int result;

	result = get_memory_ranges_iomem(array, &count);

	*range = result ? NULL : array;
	*ranges = result ? 0 : count;

	return result;
}

int arch_compat_trampoline(struct kexec_info *info)
{
	return 0;
}

int machine_verify_elf_rel(struct mem_ehdr *ehdr)
{
	return (ehdr->e_machine == EM_AARCH64);
}

void machine_apply_elf_rel(struct mem_ehdr *ehdr, struct mem_sym *UNUSED(sym),
	unsigned long r_type, void *ptr, unsigned long address,
	unsigned long value)
{
#if !defined(R_AARCH64_ABS64)
# define R_AARCH64_ABS64 257
#endif

#if !defined(R_AARCH64_PREL32)
# define R_AARCH64_PREL32 261
#endif

#if !defined(R_AARCH64_LD_PREL_LO19)
# define R_AARCH64_LD_PREL_LO19 273
#endif

#if !defined(R_AARCH64_ADR_PREL_LO21)
# define R_AARCH64_ADR_PREL_LO21 274
#endif

#if !defined(R_AARCH64_ADR_PREL_PG_HI21)
# define R_AARCH64_ADR_PREL_PG_HI21 275
#endif

#if !defined(R_AARCH64_ADD_ABS_LO12_NC)
# define R_AARCH64_ADD_ABS_LO12_NC 277
#endif

#if !defined(R_AARCH64_JUMP26)
# define R_AARCH64_JUMP26 282
#endif

#if !defined(R_AARCH64_CALL26)
# define R_AARCH64_CALL26 283
#endif

#if !defined(R_AARCH64_LDST64_ABS_LO12_NC)
# define R_AARCH64_LDST64_ABS_LO12_NC 286
#endif

	uint64_t *loc64;
	uint32_t *loc32;
	uint64_t *location = (uint64_t *)ptr;
	uint64_t data = *location;
	uint64_t imm;
	const char *type = NULL;

	switch(r_type) {
	case R_AARCH64_ABS64:
		type = "ABS64";
		loc64 = ptr;
		*loc64 = cpu_to_elf64(ehdr, elf64_to_cpu(ehdr, *loc64) + value);
		break;
	case R_AARCH64_PREL32:
		type = "PREL32";
		loc32 = ptr;
		*loc32 = cpu_to_elf32(ehdr,
			elf32_to_cpu(ehdr, *loc32) + value - address);
		break;
	case R_AARCH64_LD_PREL_LO19:
		type = "LD_PREL_LO19";
		loc32 = ptr;
		*loc32 = cpu_to_le32(le32_to_cpu(*loc32)
			+ (((value - address) << 3) & 0xffffe0));
		break;
	case R_AARCH64_ADR_PREL_LO21:
		if (value & 3)
			die("%s: ERROR Unaligned value: %lx\n", __func__,
				value);
		type = "ADR_PREL_LO21";
		loc32 = ptr;
		*loc32 = cpu_to_le32(le32_to_cpu(*loc32)
			+ (((value - address) << 3) & 0xffffe0));
		break;
	case R_AARCH64_ADR_PREL_PG_HI21:
		type = "ADR_PREL_PG_HI21";
		imm = ((value & ~0xfff) - (address & ~0xfff)) >> 12;
		loc32 = ptr;
		*loc32 = cpu_to_le32(le32_to_cpu(*loc32)
			+ ((imm & 3) << 29) + ((imm & 0x1ffffc) << (5 - 2)));
		break;
	case R_AARCH64_ADD_ABS_LO12_NC:
		type = "ADD_ABS_LO12_NC";
		loc32 = ptr;
		*loc32 = cpu_to_le32(le32_to_cpu(*loc32)
			+ ((value & 0xfff) << 10));
		break;
	case R_AARCH64_JUMP26:
		type = "JUMP26";
		loc32 = ptr;
		*loc32 = cpu_to_le32(le32_to_cpu(*loc32)
			+ (((value - address) >> 2) & 0x3ffffff));
		break;
	case R_AARCH64_CALL26:
		type = "CALL26";
		loc32 = ptr;
		*loc32 = cpu_to_le32(le32_to_cpu(*loc32)
			+ (((value - address) >> 2) & 0x3ffffff));
		break;
	case R_AARCH64_LDST64_ABS_LO12_NC:
		if (value & 7)
			die("%s: ERROR Unaligned value: %lx\n", __func__,
				value);
		type = "LDST64_ABS_LO12_NC";
		loc32 = ptr;
		*loc32 = cpu_to_le32(le32_to_cpu(*loc32)
			+ ((value & 0xff8) << (10 - 3)));
		break;
	default:
		die("%s: ERROR Unknown type: %lu\n", __func__, r_type);
		break;
	}

	dbgprintf("%s: %s %016lx->%016lx\n", __func__, type, data, *location);
}

void arch_reuse_initrd(void)
{
	reuse_initrd = 1;
}

void arch_update_purgatory(struct kexec_info *UNUSED(info))
{
}
