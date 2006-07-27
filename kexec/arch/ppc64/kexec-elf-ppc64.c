/*
 * kexec: Linux boots Linux
 *
 * Copyright (C) 2004  Adam Litke (agl@us.ibm.com)
 * Copyright (C) 2004  IBM Corp.
 * Copyright (C) 2005  R Sharada (sharada@in.ibm.com)
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

#define OPT_APPEND     (OPT_ARCH_MAX+0)
#define OPT_RAMDISK     (OPT_ARCH_MAX+1)
#define OPT_DEVICETREEBLOB     (OPT_ARCH_MAX+2)

	static const struct option options[] = {
		KEXEC_ARCH_OPTIONS
		{ "command-line",       1, NULL, OPT_APPEND },
		{ "append",             1, NULL, OPT_APPEND },
		{ "ramdisk",            1, NULL, OPT_RAMDISK },
		{ "devicetreeblob",     1, NULL, OPT_DEVICETREEBLOB },
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
			0xFFFFFFFFFFFFFFFFUL, 1);
	ehdr.e_phdr[0].p_paddr = hole_addr;
	result = elf_exec_load(&ehdr, info);
	if (result < 0) {
		free_elf_info(&ehdr);
		return result;
	}

	/* Add a ram-disk to the current image */
	if (ramdisk) {
		if (devicetreeblob) {
			fprintf(stderr, "Can't use ramdisk with device tree blob input\n");
			return -1;
		}
		unsigned char *ramdisk_buf = NULL;
		off_t ramdisk_size = 0;
		unsigned long long ramdisk_addr;

		ramdisk_buf = slurp_file(ramdisk, &ramdisk_size);
		add_buffer(info, ramdisk_buf, ramdisk_size, ramdisk_size, 0, 0,
				0xFFFFFFFFFFFFFFFFUL, 1);
		ramdisk_addr = (unsigned long long)info->segment[info->nr_segments-1].mem;
		initrd_base = ramdisk_addr;
		initrd_size = ramdisk_size;
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
	unsigned char *v2wrap_buf = NULL;
	off_t v2wrap_size = 0;
	unsigned long long *rsvmap_ptr;
	struct bootblock *bb_ptr;
	unsigned int devtree_size;

	v2wrap_buf = (char *) malloc(purgatory_size);
	if (v2wrap_buf == NULL) {
		free_elf_info(&ehdr);
		return -1;
	}
	memcpy(v2wrap_buf, purgatory, purgatory_size);
	v2wrap_size = purgatory_size;
	if (devicetreeblob) {
	  unsigned char *blob_buf = NULL;
	  off_t blob_size = 0;
	  unsigned char *tmp_buf = NULL;

	  /* Grab device tree from buffer */
	  blob_buf = slurp_file(devicetreeblob, &blob_size);

	  /* Append to purgatory */
	  tmp_buf = (unsigned char *) realloc(v2wrap_buf, v2wrap_size + blob_size);
	  v2wrap_buf = tmp_buf;
	  memcpy(v2wrap_buf+v2wrap_size, blob_buf, blob_size);
	  v2wrap_size += blob_size;

	} else {
	  /* create from fs2dt */
	  create_flatten_tree(info, &v2wrap_buf, &v2wrap_size);
	}
	add_buffer(info, v2wrap_buf, v2wrap_size, v2wrap_size, 0, 0,
			0xFFFFFFFFFFFFFFFFUL, -1);

	/* patch reserve map address for flattened device-tree
	   find last entry (both 0) in the reserve mem list.  Assume DT
	   entry is before this one */
	bb_ptr = (struct bootblock *)(
		(unsigned char *)info->segment[(info->nr_segments)-1].buf +
		0x100);
	rsvmap_ptr = (long long *)(
		(unsigned char *)info->segment[(info->nr_segments)-1].buf +
		bb_ptr->off_mem_rsvmap + 0x100);
	while (*rsvmap_ptr || *(rsvmap_ptr+1)){
		rsvmap_ptr += 2;
	}
	rsvmap_ptr -= 2;
	*rsvmap_ptr = (unsigned long long)(
		info->segment[(info->nr_segments)-1].mem + 0x100);
 	rsvmap_ptr++;
 	*rsvmap_ptr = (unsigned long long)bb_ptr->totalsize;

	unsigned int nr_segments;
	nr_segments = info->nr_segments;
	lp = info->segment[nr_segments-1].buf + 0x100;
	lp--;
	*lp = info->segment[0].mem;
	info->entry = info->segment[nr_segments-1].mem;

	unsigned int i;
	for (i = 0; i < nr_segments; i++)
		printf("segment[i].mem:%lx\n", info->segment[i].mem);

	return 0;
}

void elf_ppc64_usage(void)
{
	fprintf(stderr, "elf support is still broken\n");
}
