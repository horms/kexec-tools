/*
 * kexec: Linux boots Linux
 *
 * Copyright (C) 2003,2004  Eric Biederman (ebiederm@xmission.com)
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
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fb.h>
#include <unistd.h>
#include <x86/x86-linux.h>
#include "../../kexec.h"
#include "kexec-x86.h"
#include "x86-linux-setup.h"

void init_linux_parameters(struct x86_linux_param_header *real_mode)
{
	/* Fill in the values that are usually provided by the kernel. */

	/* Boot block magic */
	memcpy(real_mode->header_magic, "HdrS", 4);
	real_mode->protocol_version = 0x0206;
	real_mode->initrd_addr_max = DEFAULT_INITRD_ADDR_MAX;
	real_mode->cmdline_size = COMMAND_LINE_SIZE;
}

void setup_linux_bootloader_parameters(
	struct kexec_info *info, struct x86_linux_param_header *real_mode,
	unsigned long real_mode_base, unsigned long cmdline_offset,
	const char *cmdline, off_t cmdline_len,
	const unsigned char *initrd_buf, off_t initrd_size)
{
	char *cmdline_ptr;
	unsigned long initrd_base, initrd_addr_max;

	/* Say I'm a boot loader */
	real_mode->loader_type = LOADER_TYPE_UNKNOWN;

	/* No loader flags */
	real_mode->loader_flags = 0;

	/* Find the maximum initial ramdisk address */
	initrd_addr_max = DEFAULT_INITRD_ADDR_MAX;
	if (real_mode->protocol_version >= 0x0203) {
		initrd_addr_max = real_mode->initrd_addr_max;
		dbgprintf("initrd_addr_max is 0x%lx\n", initrd_addr_max);
	}

	/* Load the initrd if we have one */
	if (initrd_buf) {
		initrd_base = add_buffer(info,
			initrd_buf, initrd_size, initrd_size,
			4096, INITRD_BASE, initrd_addr_max, -1);
		dbgprintf("Loaded initrd at 0x%lx size 0x%lx\n", initrd_base,
			initrd_size);
	} else {
		initrd_base = 0;
		initrd_size = 0;
	}

	/* Ramdisk address and size */
	real_mode->initrd_start = initrd_base;
	real_mode->initrd_size  = initrd_size;

	/* The location of the command line */
	/* if (real_mode_base == 0x90000) { */
		real_mode->cl_magic = CL_MAGIC_VALUE;
		real_mode->cl_offset = cmdline_offset;
		/* setup_move_size */
	/* } */
	if (real_mode->protocol_version >= 0x0202) {
		real_mode->cmd_line_ptr = real_mode_base + cmdline_offset;
	}

	/* Fill in the command line */
	if (cmdline_len > COMMAND_LINE_SIZE) {
		cmdline_len = COMMAND_LINE_SIZE;
	}
	cmdline_ptr = ((char *)real_mode) + cmdline_offset;
	memcpy(cmdline_ptr, cmdline, cmdline_len);
	cmdline_ptr[cmdline_len - 1] = '\0';
}

int setup_linux_vesafb(struct x86_linux_param_header *real_mode)
{
	struct fb_fix_screeninfo fix;
	struct fb_var_screeninfo var;
	int fd;

	fd = open("/dev/fb0", O_RDONLY);
	if (-1 == fd)
		return -1;

	if (-1 == ioctl(fd, FBIOGET_FSCREENINFO, &fix))
		goto out;
	if (-1 == ioctl(fd, FBIOGET_VSCREENINFO, &var))
		goto out;
	if (0 == strcmp(fix.id, "VESA VGA")) {
		/* VIDEO_TYPE_VLFB */
		real_mode->orig_video_isVGA = 0x23;
	} else if (0 == strcmp(fix.id, "EFI VGA")) {
		/* VIDEO_TYPE_EFI */
		real_mode->orig_video_isVGA = 0x70;
	} else {
		/* cannot handle and other types */
		goto out;
	}
	close(fd);

	real_mode->lfb_width      = var.xres;
	real_mode->lfb_height     = var.yres;
	real_mode->lfb_depth      = var.bits_per_pixel;
	real_mode->lfb_base       = fix.smem_start;
	real_mode->lfb_linelength = fix.line_length;
	real_mode->vesapm_seg     = 0;

	/* FIXME: better get size from the file returned by proc_iomem() */
	real_mode->lfb_size       = (fix.smem_len + 65535) / 65536;
	real_mode->pages          = (fix.smem_len + 4095) / 4096;

	if (var.bits_per_pixel > 8) {
		real_mode->red_pos    = var.red.offset;
		real_mode->red_size   = var.red.length;
		real_mode->green_pos  = var.green.offset;
		real_mode->green_size = var.green.length;
		real_mode->blue_pos   = var.blue.offset;
		real_mode->blue_size  = var.blue.length;
		real_mode->rsvd_pos   = var.transp.offset;
		real_mode->rsvd_size  = var.transp.length;
	}
	fprintf(stderr, "%s: %dx%dx%d @ %lx +%x\n", __FUNCTION__,
		var.xres, var.yres, var.bits_per_pixel,
		fix.smem_start, fix.smem_len);
	return 0;

 out:
	close(fd);
	return -1;
}

void setup_linux_system_parameters(struct x86_linux_param_header *real_mode,
					unsigned long kexec_flags)
{
	/* Fill in information the BIOS would usually provide */
	struct memory_range *range;
	int i, ranges;
	
	/* Default screen size */
	real_mode->orig_x = 0;
	real_mode->orig_y = 0;
	real_mode->orig_video_page = 0;
	real_mode->orig_video_mode = 0;
	real_mode->orig_video_cols = 80;
	real_mode->orig_video_lines = 25;
	real_mode->orig_video_ega_bx = 0;
	real_mode->orig_video_isVGA = 1;
	real_mode->orig_video_points = 16;
	setup_linux_vesafb(real_mode);

	/* Fill in the memsize later */
	real_mode->ext_mem_k = 0;
	real_mode->alt_mem_k = 0;
	real_mode->e820_map_nr = 0;

	/* Default APM info */
	memset(&real_mode->apm_bios_info, 0, sizeof(real_mode->apm_bios_info));
	/* Default drive info */
	memset(&real_mode->drive_info, 0, sizeof(real_mode->drive_info));
	/* Default sysdesc table */
	real_mode->sys_desc_table.length = 0;

	/* default yes: this can be overridden on the command line */
	real_mode->mount_root_rdonly = 0xFFFF;

	/* default /dev/hda
	 * this can be overrident on the command line if necessary.
	 */
	real_mode->root_dev = (0x3 <<8)| 0;

	/* another safe default */
	real_mode->aux_device_info = 0;

	/* Fill in the memory info */
	if ((get_memory_ranges(&range, &ranges, kexec_flags) < 0) || ranges == 0) {
		die("Cannot get memory information\n");
	}
	if (ranges > E820MAX) {
		fprintf(stderr, "Too many memory ranges, truncating...\n");
		ranges = E820MAX;
	}
	real_mode->e820_map_nr = ranges;
	for(i = 0; i < ranges; i++) {
		real_mode->e820_map[i].addr = range[i].start;
		real_mode->e820_map[i].size = range[i].end - range[i].start;
		switch (range[i].type) {
		case RANGE_RAM:
			real_mode->e820_map[i].type = E820_RAM; 
			break;
		case RANGE_ACPI:
			real_mode->e820_map[i].type = E820_ACPI; 
			break;
		case RANGE_ACPI_NVS:
			real_mode->e820_map[i].type = E820_NVS;
			break;
		default:
		case RANGE_RESERVED:
			real_mode->e820_map[i].type = E820_RESERVED; 
			break;
		}
		if (range[i].type != RANGE_RAM)
			continue;
		if ((range[i].start <= 0x100000) && range[i].end > 0x100000) {
			unsigned long long mem_k = (range[i].end >> 10) - (0x100000 >> 10);
			real_mode->ext_mem_k = mem_k;
			real_mode->alt_mem_k = mem_k;
			if (mem_k > 0xfc00) {
				real_mode->ext_mem_k = 0xfc00; /* 64M */
			}
			if (mem_k > 0xffffffff) {
				real_mode->alt_mem_k = 0xffffffff;
			}
		}
	}
}
