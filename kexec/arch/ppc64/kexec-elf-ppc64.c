/*
 * kexec: Linux boots Linux
 *
 * Copyright (C) 2004  Adam Litke (agl@us.ibm.com)
 * Copyright (C) 2004  IBM Corp.
 * Copyright (C) 2005  R Sharada (sharada@in.ibm.com)
 * Copyright (C) 2006  Mohan Kumar M (mohan@in.ibm.com)
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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <linux/elf.h>
#include "../../kexec.h"
#include "../../kexec-elf.h"
#include "../../kexec-syscall.h"
#include "kexec-ppc64.h"
#include "crashdump-ppc64.h"
#include <arch/options.h>

#define BOOTLOADER         "kexec"
#define BOOTLOADER_VERSION VERSION

unsigned long initrd_base, initrd_size;

int create_flatten_tree(struct kexec_info *, unsigned char **, unsigned long *,
			char *);
int my_r2(struct mem_ehdr *ehdr);

int elf_ppc64_probe(const char *buf, off_t len)
{
	struct mem_ehdr ehdr;
	int result;
	result = build_elf_exec_info(buf, len, &ehdr);
	if (result < 0) {
		goto out;
	}

	/* Verify the architecuture specific bits */
	if ((ehdr.e_machine != EM_PPC64) && (ehdr.e_machine != EM_PPC)) {
		/* for a different architecture */
		result = -1;
		goto out;
	}
	result = 0;
 out:
	free_elf_info(&ehdr);
	return result;
}

int elf_ppc64_load(int argc, char **argv, const char *buf, off_t len,
			struct kexec_info *info)
{
	struct mem_ehdr ehdr;
	char *cmdline, *modified_cmdline;
	const char *ramdisk, *devicetreeblob;
	int cmdline_len, modified_cmdline_len;
	unsigned long long max_addr, hole_addr;
	unsigned char *seg_buf = NULL;
	off_t seg_size = 0;
	struct mem_phdr *phdr;
	size_t size;
	unsigned long long *rsvmap_ptr;
	struct bootblock *bb_ptr;
	unsigned int nr_segments, i;
	int result, opt;
	unsigned long my_kernel, my_dt_offset;
	unsigned int my_panic_kernel;
	unsigned long my_stack, my_backup_start;
	unsigned long toc_addr;

#define OPT_APPEND     (OPT_ARCH_MAX+0)
#define OPT_RAMDISK     (OPT_ARCH_MAX+1)
#define OPT_DEVICETREEBLOB     (OPT_ARCH_MAX+2)
#define OPT_ARGS_IGNORE		(OPT_ARCH_MAX+3)

	static const struct option options[] = {
		KEXEC_ARCH_OPTIONS
		{ "command-line",       1, NULL, OPT_APPEND },
		{ "append",             1, NULL, OPT_APPEND },
		{ "ramdisk",            1, NULL, OPT_RAMDISK },
		{ "initrd",             1, NULL, OPT_RAMDISK },
		{ "devicetreeblob",     1, NULL, OPT_DEVICETREEBLOB },
		{ "args-linux",		0, NULL, OPT_ARGS_IGNORE },
		{ 0,                    0, NULL, 0 },
	};

	static const char short_options[] = KEXEC_OPT_STR "";

	/* Parse command line arguments */
	initrd_base = 0;
	initrd_size = 0;
	cmdline = 0;
	ramdisk = 0;
	devicetreeblob = 0;
	max_addr = 0xFFFFFFFFFFFFFFFFUL;
	hole_addr = 0;

	while ((opt = getopt_long(argc, argv, short_options,
					options, 0)) != -1) {
		switch (opt) {
		default:
			/* Ignore core options */
			if (opt < OPT_ARCH_MAX)
				break;
		case '?':
			usage();
			return -1;
		case OPT_APPEND:
			cmdline = optarg;
			break;
		case OPT_RAMDISK:
			ramdisk = optarg;
			break;
		case OPT_DEVICETREEBLOB:
			devicetreeblob = optarg;
			break;
		case OPT_ARGS_IGNORE:
			break;
		}
	}

	cmdline_len = 0;
	if (cmdline)
		cmdline_len = strlen(cmdline) + 1;

	setup_memory_ranges(info->kexec_flags);

	/* Need to append some command line parameters internally in case of
	 * taking crash dumps.
	 */
	if (info->kexec_flags & KEXEC_ON_CRASH) {
		modified_cmdline = xmalloc(COMMAND_LINE_SIZE);
		memset((void *)modified_cmdline, 0, COMMAND_LINE_SIZE);
		if (cmdline) {
			strncpy(modified_cmdline, cmdline, COMMAND_LINE_SIZE);
			modified_cmdline[COMMAND_LINE_SIZE - 1] = '\0';
		}
		modified_cmdline_len = strlen(modified_cmdline);
	}

	/* Parse the Elf file */
	result = build_elf_exec_info(buf, len, &ehdr);
	if (result < 0) {
		free_elf_info(&ehdr);
		return result;
	}

	/* Load the Elf data. Physical load addresses in elf64 header do not
	 * show up correctly. Use user supplied address for now to patch the
	 * elf header
	 */

	phdr = &ehdr.e_phdr[0];
	size = phdr->p_filesz;
	if (size > phdr->p_memsz)
		size = phdr->p_memsz;

	hole_addr = (unsigned long)locate_hole(info, size, 0, 0,
			max_addr, 1);
	ehdr.e_phdr[0].p_paddr = hole_addr;
	result = elf_exec_load(&ehdr, info);
	if (result < 0) {
		free_elf_info(&ehdr);
		return result;
	}

	/* If panic kernel is being loaded, additional segments need
	 * to be created.
	 */
	if (info->kexec_flags & KEXEC_ON_CRASH) {
		result = load_crashdump_segments(info, modified_cmdline,
						max_addr, 0);
		if (result < 0)
			return -1;
		/* Use new command line. */
		cmdline = modified_cmdline;
		cmdline_len = strlen(modified_cmdline) + 1;
	}

	/* Add v2wrap to the current image */
	seg_buf = NULL;
	seg_size = 0;

	seg_buf = (unsigned char *) malloc(purgatory_size);
	if (seg_buf == NULL) {
		free_elf_info(&ehdr);
		return -1;
	}
	memcpy(seg_buf, purgatory, purgatory_size);
	seg_size = purgatory_size;
	elf_rel_build_load(info, &info->rhdr, (const char *)purgatory,
				purgatory_size, 0, max_addr, 1);

	/* Add a ram-disk to the current image
	 * Note: Add the ramdisk after elf_rel_build_load
	 */
	if (ramdisk) {
		if (devicetreeblob) {
			fprintf(stderr,
			"Can't use ramdisk with device tree blob input\n");
			return -1;
		}
		seg_buf = (unsigned char *)slurp_file(ramdisk, &seg_size);
		add_buffer(info, seg_buf, seg_size, seg_size, 0, 0, max_addr, 1);
		hole_addr = (unsigned long long)
			info->segment[info->nr_segments-1].mem;
		initrd_base = hole_addr;
		initrd_size = (unsigned long long)
			info->segment[info->nr_segments-1].memsz;
	} /* ramdisk */

	if (devicetreeblob) {
		unsigned char *blob_buf = NULL;
		off_t blob_size = 0;

		/* Grab device tree from buffer */
		blob_buf =
			(unsigned char *)slurp_file(devicetreeblob, &blob_size);
		add_buffer(info, blob_buf, blob_size, blob_size, 0, 0,
				max_addr, -1);

	} else {
		/* create from fs2dt */
		seg_buf = NULL;
		seg_size = 0;
		create_flatten_tree(info, (unsigned char **)&seg_buf,
				(unsigned long *)&seg_size,cmdline);
		add_buffer(info, seg_buf, seg_size, seg_size,
				0, 0, max_addr, -1);
	}

	/* patch reserve map address for flattened device-tree
	 * find last entry (both 0) in the reserve mem list.  Assume DT
	 * entry is before this one
	 */
	bb_ptr = (struct bootblock *)(
		(unsigned char *)info->segment[(info->nr_segments)-1].buf);
	rsvmap_ptr = (unsigned long long *)(
		(unsigned char *)info->segment[(info->nr_segments)-1].buf +
		bb_ptr->off_mem_rsvmap);
	while (*rsvmap_ptr || *(rsvmap_ptr+1))
		rsvmap_ptr += 2;
	rsvmap_ptr -= 2;
	*rsvmap_ptr = (unsigned long long)(
		info->segment[(info->nr_segments)-1].mem);
	rsvmap_ptr++;
	*rsvmap_ptr = (unsigned long long)bb_ptr->totalsize;

	nr_segments = info->nr_segments;

	/* Set kernel */
	my_kernel = (unsigned long )info->segment[0].mem;
	elf_rel_set_symbol(&info->rhdr, "kernel", &my_kernel, sizeof(my_kernel));

	/* Set dt_offset */
	my_dt_offset = (unsigned long )info->segment[nr_segments-1].mem;
	elf_rel_set_symbol(&info->rhdr, "dt_offset", &my_dt_offset,
				sizeof(my_dt_offset));

	if (info->kexec_flags & KEXEC_ON_CRASH) {
		my_panic_kernel = 1;
		/* Set panic flag */
		elf_rel_set_symbol(&info->rhdr, "panic_kernel",
				&my_panic_kernel, sizeof(my_panic_kernel));

		/* Set backup address */
		my_backup_start = info->backup_start;
		elf_rel_set_symbol(&info->rhdr, "backup_start",
				&my_backup_start, sizeof(my_backup_start));
	}

	/* Set stack address */
	my_stack = locate_hole(info, 16*1024, 0, 0, max_addr, 1);
	my_stack += 16*1024;
	elf_rel_set_symbol(&info->rhdr, "stack", &my_stack, sizeof(my_stack));

	/* Set toc */
	toc_addr = (unsigned long) my_r2(&info->rhdr);
	elf_rel_set_symbol(&info->rhdr, "my_toc", &toc_addr, sizeof(toc_addr));

#ifdef DEBUG
	my_kernel = 0;
	my_dt_offset = 0;
	my_panic_kernel = 0;
	my_backup_start = 0;
	my_stack = 0;
	toc_addr = 0;

	elf_rel_get_symbol(&info->rhdr, "kernel", &my_kernel, sizeof(my_kernel));
	elf_rel_get_symbol(&info->rhdr, "dt_offset", &my_dt_offset,
				sizeof(my_dt_offset));
	elf_rel_get_symbol(&info->rhdr, "panic_kernel", &my_panic_kernel,
				sizeof(my_panic_kernel));
	elf_rel_get_symbol(&info->rhdr, "backup_start", &my_backup_start,
				sizeof(my_backup_start));
	elf_rel_get_symbol(&info->rhdr, "stack", &my_stack, sizeof(my_stack));
	elf_rel_get_symbol(&info->rhdr, "my_toc", &toc_addr,
				sizeof(toc_addr));

	fprintf(stderr, "info->entry is %p\n", info->entry);
	fprintf(stderr, "kernel is %Lx\n", my_kernel);
	fprintf(stderr, "dt_offset is %Lx\n", my_dt_offset);
	fprintf(stderr, "panic_kernel is %x\n", my_panic_kernel);
	fprintf(stderr, "backup_start is %Lx\n", my_backup_start);
	fprintf(stderr, "stack is %Lx\n", my_stack);
	fprintf(stderr, "toc_addr is %Lx\n", toc_addr);
	fprintf(stderr, "purgatory size is %d\n", purgatory_size);
#endif

	for (i = 0; i < nr_segments; i++)
		fprintf(stderr, "segment[%d].mem:%p memsz:%ld\n", i,
			info->segment[i].mem, info->segment[i].memsz);

	return 0;
}

void elf_ppc64_usage(void)
{
	fprintf(stderr, "elf support is still broken\n");
}
