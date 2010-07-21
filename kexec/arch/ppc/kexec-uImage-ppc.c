/*
 * uImage support for PowerPC
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <image.h>
#include <getopt.h>
#include <arch/options.h>
#include "../../kexec.h"
#include "../../kexec-syscall.h"
#include "kexec-ppc.h"
#include "fixup_dtb.h"
#include <kexec-uImage.h>
#include "crashdump-powerpc.h"
#include <limits.h>

int create_flatten_tree(struct kexec_info *, unsigned char **, unsigned long *,
			char *);

/* See options.h -- add any more there, too. */
static const struct option options[] = {
	KEXEC_ARCH_OPTIONS
	{"command-line",	1, 0, OPT_APPEND},
	{"append",	1, 0, OPT_APPEND},
	{"ramdisk",	1, 0, OPT_RAMDISK},
	{"initrd",	1, 0, OPT_RAMDISK},
	{"dtb",		1, 0, OPT_DTB},
	{"reuse-node",	1, 0, OPT_NODES},
	{0, 0, 0, 0},
};
static const char short_options[] = KEXEC_ARCH_OPT_STR;

void uImage_ppc_usage(void)
{
	printf(
			"    --command-line=STRING Set the kernel command line to STRING.\n"
			"    --append=STRING       Set the kernel command line to STRING.\n"
			"    --ramdisk=<filename>  Initial RAM disk.\n"
			"    --initrd=<filename>   same as --ramdisk\n"
			"    --dtb=<filename>      Specify device tree blob file.\n"
			"    --reuse-node=node     Specify nodes which should be taken from /proc/device-tree.\n"
			"                          Can be set multiple times.\n"
	);
}

int uImage_ppc_probe(const char *buf, off_t len)
{
	return uImage_probe(buf, len, IH_ARCH_PPC);
}

static int ppc_load_bare_bits(int argc, char **argv, const char *buf,
		off_t len, struct kexec_info *info, unsigned int load_addr,
		unsigned int ep)
{
	char *command_line, *cmdline_buf, *crash_cmdline;
	int command_line_len;
	char *dtb;
	unsigned int addr;
	unsigned long dtb_addr;
	unsigned long dtb_addr_actual;
#define FIXUP_ENTRYS    (20)
	char *fixup_nodes[FIXUP_ENTRYS + 1];
	int cur_fixup = 0;
	int opt;
	int ret;
	char *seg_buf = NULL;
	off_t seg_size = 0;
	unsigned long long hole_addr;
	unsigned long max_addr;
	char *blob_buf = NULL;
	off_t blob_size = 0;

	cmdline_buf = NULL;
	command_line = NULL;
	dtb = NULL;
	max_addr = LONG_MAX;

	while ((opt = getopt_long(argc, argv, short_options, options, 0)) != -1) {
		switch (opt) {
		default:
			/* Ignore core options */
			if (opt < OPT_ARCH_MAX) {
				break;
			}
		case '?':
			usage();
			return -1;
		case OPT_APPEND:
			command_line = optarg;
			break;

		case OPT_RAMDISK:
			ramdisk = optarg;
			break;

		case OPT_DTB:
			dtb = optarg;
			break;

		case OPT_NODES:
			if (cur_fixup >= FIXUP_ENTRYS) {
				fprintf(stderr, "The number of entries for the fixup is too large\n");
				exit(1);
			}
			fixup_nodes[cur_fixup] = optarg;
			cur_fixup++;
			break;
		}
	}

	if (ramdisk && reuse_initrd)
		die("Can't specify --ramdisk or --initrd with --reuseinitrd\n");

	command_line_len = 0;
	if (command_line) {
		command_line_len = strlen(command_line) + 1;
	} else {
		command_line = get_command_line();
		command_line_len = strlen(command_line) + 1;
	}

	fixup_nodes[cur_fixup] = NULL;

	/*
	 * len contains the length of the whole kernel image except the bss
	 * section. The 1 MiB should cover it. The purgatory and the dtb are
	 * allocated from memtop down towards zero so we should never get too
	 * close to the bss :)
	 */
	ret = valid_memory_range(info, load_addr, load_addr + (len + (1 * 1024 * 1024)));
	if (!ret) {
		printf("Can't add kernel to addr 0x%08x len %ld\n",
				load_addr, len + (1 * 1024 * 1024));
		return -1;
	}
	add_segment(info, buf, len, load_addr, len + (1 * 1024 * 1024));

	if (info->kexec_flags & KEXEC_ON_CRASH) {
                crash_cmdline = xmalloc(COMMAND_LINE_SIZE);
                memset((void *)crash_cmdline, 0, COMMAND_LINE_SIZE);
        } else
                crash_cmdline = NULL;

	if (info->kexec_flags & KEXEC_ON_CRASH) {
		ret = load_crashdump_segments(info, crash_cmdline,
						max_addr, 0);
		if (ret < 0) {
			return -1;
		}
	}

	cmdline_buf = xmalloc(COMMAND_LINE_SIZE);
	memset((void *)cmdline_buf, 0, COMMAND_LINE_SIZE);
	if (command_line)
		strncat(cmdline_buf, command_line, command_line_len);
	if (crash_cmdline)
		strncat(cmdline_buf, crash_cmdline,
			sizeof(crash_cmdline) -
			strlen(crash_cmdline) - 1);

	elf_rel_build_load(info, &info->rhdr, (const char *)purgatory,
				purgatory_size, 0, -1, -1, 0);

	/* Here we need to initialize the device tree, and find out where
	 * it is going to live so we can place it directly after the
	 * kernel image */
	if (dtb) {
		/* Grab device tree from buffer */
		blob_buf = slurp_file(dtb, &blob_size);
	} else {
		create_flatten_tree(info, (unsigned char **)&blob_buf,
				(unsigned long *)&blob_size, cmdline_buf);
	}
	if (!blob_buf || !blob_size)
		die("Device tree seems to be an empty file.\n");

	/* initial fixup for device tree */
	blob_buf = fixup_dtb_init(info, blob_buf, &blob_size, load_addr, &dtb_addr);

	if (ramdisk) {
		seg_buf = slurp_file(ramdisk, &seg_size);
		/* Load ramdisk at top of memory */
		hole_addr = add_buffer(info, seg_buf, seg_size, seg_size,
				0, dtb_addr + blob_size, max_addr, -1);
		ramdisk_base = hole_addr;
		ramdisk_size = seg_size;
	}
	if (reuse_initrd) {
		ramdisk_base = initrd_base;
		ramdisk_size = initrd_size;
	}

	if (info->kexec_flags & KEXEC_ON_CRASH && ramdisk_base != 0) {
		if ( (ramdisk_base < crash_base) ||
		     (ramdisk_base > crash_base + crash_size) ) {
			printf("WARNING: ramdisk is above crashkernel region!\n");
		}
		else if (ramdisk_base + ramdisk_size > crash_base + crash_size) {
			printf("WARNING: ramdisk overflows crashkernel region!\n");
		}
	}

	/* Perform final fixup on devie tree, i.e. everything beside what
	 * was done above */
	fixup_dtb_finalize(info, blob_buf, &blob_size, fixup_nodes,
			cmdline_buf);
	dtb_addr_actual = add_buffer(info, blob_buf, blob_size, blob_size, 0, dtb_addr,
			load_addr + KERNEL_ACCESS_TOP, 1);
	if (dtb_addr_actual != dtb_addr) {
		printf("dtb_addr_actual: %lx, dtb_addr: %lx\n", dtb_addr_actual, dtb_addr);
		die("Error device tree not loadded to address it was expecting to be loaded too!\n");
	}

	/* set various variables for the purgatory */
	addr = ep;
	elf_rel_set_symbol(&info->rhdr, "kernel", &addr, sizeof(addr));

	addr = dtb_addr;
	elf_rel_set_symbol(&info->rhdr, "dt_offset", &addr, sizeof(addr));

#define PUL_STACK_SIZE  (16 * 1024)
	addr = locate_hole(info, PUL_STACK_SIZE, 0, 0, -1, 1);
	addr += PUL_STACK_SIZE;
	elf_rel_set_symbol(&info->rhdr, "stack", &addr, sizeof(addr));
	/* No allocation past here in order not to overwrite the stack */
#undef PUL_STACK_SIZE

	addr = elf_rel_get_addr(&info->rhdr, "purgatory_start");
	info->entry = (void *)addr;

	return 0;
}

int uImage_ppc_load(int argc, char **argv, const char *buf, off_t len,
		struct kexec_info *info)
{
	struct Image_info img;
	int ret;

	ret = uImage_load(buf, len, &img);
	if (ret)
		return ret;

	return	ppc_load_bare_bits(argc, argv, img.buf, img.len, info,
				img.base, img.ep);
}
