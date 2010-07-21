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
#include "kexec-ppc.h"
#include "fixup_dtb.h"
#include <kexec-uImage.h>

/* See options.h -- add any more there, too. */
static const struct option options[] = {
	KEXEC_ARCH_OPTIONS
	{"command-line",	1, 0, OPT_APPEND},
	{"append",	1, 0, OPT_APPEND},
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
			"     --dtb=<filename>     Specify device tree blob file.\n"
			"     --reuse-node=node    Specify nodes which should be taken from /proc/device-tree.\n"
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
	char *command_line;
	int command_line_len;
	char *dtb;
	unsigned int addr;
	unsigned long dtb_addr;
#define FIXUP_ENTRYS    (20)
	char *fixup_nodes[FIXUP_ENTRYS + 1];
	int cur_fixup = 0;
	int opt;
	int ret;

	command_line = NULL;
	dtb = NULL;

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

	command_line_len = 0;
	if (command_line)
		command_line_len = strlen(command_line) + 1;

	fixup_nodes[cur_fixup] = NULL;

	/*
	 * len contains the length of the whole kernel image except the bss
	 * section. The 3 MiB should cover it. The purgatory and the dtb are
	 * allocated from memtop down towards zero so we should never get too
	 * close to the bss :)
	 */
	ret = valid_memory_range(info, load_addr, len + 3 * 1024 * 1024);
	if (!ret) {
		printf("Can't add kernel to addr 0x%08x len %ld\n",
				load_addr, len + 3 * 1024 * 1024);
		return -1;
	}
	add_segment(info, buf, len, load_addr, len + 3 * 1024 * 1024);
	if (dtb) {
		char *blob_buf;
		off_t blob_size = 0;

		/* Grab device tree from buffer */
		blob_buf = slurp_file(dtb, &blob_size);
		if (!blob_buf || !blob_size)
			die("Device tree seems to be an empty file.\n");
		blob_buf = fixup_dtb_nodes(blob_buf, &blob_size, fixup_nodes, command_line);

		dtb_addr = add_buffer(info, blob_buf, blob_size, blob_size, 0, 0,
				KERNEL_ACCESS_TOP, -1);
	} else {
		dtb_addr = 0;
	}

	elf_rel_build_load(info, &info->rhdr, (const char *)purgatory,
			purgatory_size, 0, -1, -1, 0);

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
