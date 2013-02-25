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
#include <stdarg.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fb.h>
#include <unistd.h>
#include <dirent.h>
#include <mntent.h>
#include <x86/x86-linux.h>
#include "../../kexec.h"
#include "kexec-x86.h"
#include "x86-linux-setup.h"
#include "../../kexec/kexec-syscall.h"

void init_linux_parameters(struct x86_linux_param_header *real_mode)
{
	/* Fill in the values that are usually provided by the kernel. */

	/* Boot block magic */
	memcpy(real_mode->header_magic, "HdrS", 4);
	real_mode->protocol_version = 0x0206;
	real_mode->initrd_addr_max = DEFAULT_INITRD_ADDR_MAX;
	real_mode->cmdline_size = COMMAND_LINE_SIZE;
}

void setup_linux_bootloader_parameters_high(
	struct kexec_info *info, struct x86_linux_param_header *real_mode,
	unsigned long real_mode_base, unsigned long cmdline_offset,
	const char *cmdline, off_t cmdline_len,
	const char *initrd_buf, off_t initrd_size, int initrd_high)
{
	char *cmdline_ptr;
	unsigned long initrd_base, initrd_addr_max;

	/* Say I'm a boot loader */
	real_mode->loader_type = LOADER_TYPE_KEXEC << 4;

	/* No loader flags */
	real_mode->loader_flags = 0;

	/* Find the maximum initial ramdisk address */
	if (initrd_high)
		initrd_addr_max = ULONG_MAX;
	else {
		initrd_addr_max = DEFAULT_INITRD_ADDR_MAX;
		if (real_mode->protocol_version >= 0x0203) {
			initrd_addr_max = real_mode->initrd_addr_max;
			dbgprintf("initrd_addr_max is 0x%lx\n",
					 initrd_addr_max);
		}
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
	real_mode->initrd_start = initrd_base & 0xffffffffUL;
	real_mode->initrd_size  = initrd_size & 0xffffffffUL;

	if (real_mode->protocol_version >= 0x020c &&
	    (initrd_base & 0xffffffffUL) != initrd_base)
		real_mode->ext_ramdisk_image = initrd_base >> 32;

	if (real_mode->protocol_version >= 0x020c &&
	    (initrd_size & 0xffffffffUL) != initrd_size)
		real_mode->ext_ramdisk_size = initrd_size >> 32;

	/* The location of the command line */
	/* if (real_mode_base == 0x90000) { */
		real_mode->cl_magic = CL_MAGIC_VALUE;
		real_mode->cl_offset = cmdline_offset;
		/* setup_move_size */
	/* } */
	if (real_mode->protocol_version >= 0x0202) {
		unsigned long cmd_line_ptr = real_mode_base + cmdline_offset;

		real_mode->cmd_line_ptr = cmd_line_ptr & 0xffffffffUL;
		if ((real_mode->protocol_version >= 0x020c) &&
		    ((cmd_line_ptr & 0xffffffffUL) != cmd_line_ptr))
			real_mode->ext_cmd_line_ptr = cmd_line_ptr >> 32;
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
	return 0;

 out:
	close(fd);
	return -1;
}

#define EDD_SYFS_DIR "/sys/firmware/edd"

#define EDD_EXT_FIXED_DISK_ACCESS           (1 << 0)
#define EDD_EXT_DEVICE_LOCKING_AND_EJECTING (1 << 1)
#define EDD_EXT_ENHANCED_DISK_DRIVE_SUPPORT (1 << 2)
#define EDD_EXT_64BIT_EXTENSIONS            (1 << 3)

/*
 * Scans one line from a given filename. Returns on success the number of
 * items written (same like scanf()).
 */
static int file_scanf(const char *dir, const char *file, const char *scanf_line, ...)
{
	va_list argptr;
	FILE *fp;
	int retno;
	char filename[PATH_MAX];

	snprintf(filename, PATH_MAX, "%s/%s", dir, file);
	filename[PATH_MAX-1] = 0;

	fp = fopen(filename, "r");
	if (!fp) {
		return -errno;
	}

	va_start(argptr, scanf_line);
	retno = vfscanf(fp, scanf_line, argptr);
	va_end(argptr);

	fclose(fp);

	return retno;
}

static int parse_edd_extensions(const char *dir, struct edd_info *edd_info)
{
	char filename[PATH_MAX];
	char line[1024];
	uint16_t flags = 0;
	FILE *fp;

	snprintf(filename, PATH_MAX, "%s/%s", dir, "extensions");
	filename[PATH_MAX-1] = 0;

	fp = fopen(filename, "r");
	if (!fp) {
		return -errno;
	}

	while (fgets(line, 1024, fp)) {
		/*
		 * strings are in kernel source, function edd_show_extensions()
		 * drivers/firmware/edd.c
		 */
		if (strstr(line, "Fixed disk access") == line)
			flags |= EDD_EXT_FIXED_DISK_ACCESS;
		else if (strstr(line, "Device locking and ejecting") == line)
			flags |= EDD_EXT_DEVICE_LOCKING_AND_EJECTING;
		else if (strstr(line, "Enhanced Disk Drive support") == line)
			flags |= EDD_EXT_ENHANCED_DISK_DRIVE_SUPPORT;
		else if (strstr(line, "64-bit extensions") == line)
			flags |= EDD_EXT_64BIT_EXTENSIONS;
	}

	fclose(fp);

	edd_info->interface_support = flags;

	return 0;
}

static int read_edd_raw_data(const char *dir, struct edd_info *edd_info)
{
	char filename[PATH_MAX];
	FILE *fp;
	size_t read_chars;
	uint16_t len;

	snprintf(filename, PATH_MAX, "%s/%s", dir, "raw_data");
	filename[PATH_MAX-1] = 0;

	fp = fopen(filename, "r");
	if (!fp) {
		return -errno;
	}

	memset(edd_info->edd_device_params, 0, EDD_DEVICE_PARAM_SIZE);
	read_chars = fread(edd_info->edd_device_params, sizeof(uint8_t),
				EDD_DEVICE_PARAM_SIZE, fp);
	fclose(fp);

	len = ((uint16_t *)edd_info->edd_device_params)[0];
	dbgprintf("EDD raw data has length %d\n", len);

	if (read_chars < len) {
		fprintf(stderr, "BIOS reported EDD length of %hd but only "
			"%d chars read.\n", len, (int)read_chars);
		return -1;
	}

	return 0;
}

static int add_edd_entry(struct x86_linux_param_header *real_mode,
		const char *sysfs_name, int *current_edd, int *current_mbr)
{
	uint8_t devnum, version;
	uint32_t mbr_sig;
	struct edd_info *edd_info;

	if (!current_mbr || !current_edd) {
		fprintf(stderr, "%s: current_edd and current_edd "
				"must not be NULL", __FUNCTION__);
		return -1;
	}

	edd_info = &real_mode->eddbuf[*current_edd];
	memset(edd_info, 0, sizeof(struct edd_info));

	/* extract the device number */
	if (sscanf(basename(sysfs_name), "int13_dev%hhx", &devnum) != 1) {
		fprintf(stderr, "Invalid format of int13_dev dir "
				"entry: %s\n", basename(sysfs_name));
		return -1;
	}

	/* if there's a MBR signature, then add it */
	if (file_scanf(sysfs_name, "mbr_signature", "0x%x", &mbr_sig) == 1) {
		real_mode->edd_mbr_sig_buffer[*current_mbr] = mbr_sig;
		(*current_mbr)++;
		dbgprintf("EDD Device 0x%x: mbr_sig=0x%x\n", devnum, mbr_sig);
	}

	/* set the device number */
	edd_info->device = devnum;

	/* set the version */
	if (file_scanf(sysfs_name, "version", "0x%hhx", &version) != 1)
		return -1;

	edd_info->version = version;

	/* if version == 0, that's some kind of dummy entry */
	if (version != 0) {
		/* legacy_max_cylinder */
		if (file_scanf(sysfs_name, "legacy_max_cylinder", "%hu",
					&edd_info->legacy_max_cylinder) != 1) {
			fprintf(stderr, "Reading legacy_max_cylinder failed.\n");
			return -1;
		}

		/* legacy_max_head */
		if (file_scanf(sysfs_name, "legacy_max_head", "%hhu",
					&edd_info->legacy_max_head) != 1) {
			fprintf(stderr, "Reading legacy_max_head failed.\n");
			return -1;
		}

		/* legacy_sectors_per_track */
		if (file_scanf(sysfs_name, "legacy_sectors_per_track", "%hhu",
					&edd_info->legacy_sectors_per_track) != 1) {
			fprintf(stderr, "Reading legacy_sectors_per_track failed.\n");
			return -1;
		}

		/* Parse the EDD extensions */
		if (parse_edd_extensions(sysfs_name, edd_info) != 0) {
			fprintf(stderr, "Parsing EDD extensions failed.\n");
			return -1;
		}

		/* Parse the raw info */
		if (read_edd_raw_data(sysfs_name, edd_info) != 0) {
			fprintf(stderr, "Reading EDD raw data failed.\n");
			return -1;
		}
	}

	(*current_edd)++;

	return 0;
}

static void zero_edd(struct x86_linux_param_header *real_mode)
{
	real_mode->eddbuf_entries = 0;
	real_mode->edd_mbr_sig_buf_entries = 0;
	memset(real_mode->eddbuf, 0,
		EDDMAXNR * sizeof(struct edd_info));
	memset(real_mode->edd_mbr_sig_buffer, 0,
		EDD_MBR_SIG_MAX * sizeof(uint32_t));
}

void setup_edd_info(struct x86_linux_param_header *real_mode)
{
	DIR *edd_dir;
	struct dirent *cursor;
	int current_edd = 0;
	int current_mbr = 0;

	edd_dir = opendir(EDD_SYFS_DIR);
	if (!edd_dir) {
		dbgprintf(EDD_SYFS_DIR " does not exist.\n");
		return;
	}

	zero_edd(real_mode);
	while ((cursor = readdir(edd_dir))) {
		char full_dir_name[PATH_MAX];

		/* only read the entries that start with "int13_dev" */
		if (strstr(cursor->d_name, "int13_dev") != cursor->d_name)
			continue;

		snprintf(full_dir_name, PATH_MAX, "%s/%s",
				EDD_SYFS_DIR, cursor->d_name);
		full_dir_name[PATH_MAX-1] = 0;

		if (add_edd_entry(real_mode, full_dir_name, &current_edd,
					&current_mbr) != 0) {
			zero_edd(real_mode);
			goto out;
		}
	}

	real_mode->eddbuf_entries = current_edd;
	real_mode->edd_mbr_sig_buf_entries = current_mbr;

out:
	closedir(edd_dir);

	dbgprintf("Added %d EDD MBR entries and %d EDD entries.\n",
		real_mode->edd_mbr_sig_buf_entries,
		real_mode->eddbuf_entries);
}

/*
 * This really only makes sense for virtual filesystems that are only expected
 * to be mounted once (sysfs, debugsfs, proc), as it will return the first
 * instance listed in mtab.
 */
char *find_mnt_by_fsname(char *fsname)
{
	FILE *mtab;
	struct mntent *mnt;
	char *mntdir;

	mtab = setmntent("/etc/mtab", "r");
	if (!mtab)
		return NULL;
	for(mnt = getmntent(mtab); mnt; mnt = getmntent(mtab)) {
		if (strcmp(mnt->mnt_fsname, fsname) == 0)
			break;
	}
	mntdir = mnt ? strdup(mnt->mnt_dir) : NULL;
	endmntent(mtab);
	return mntdir;
}

void setup_subarch(struct x86_linux_param_header *real_mode)
{
	int data_file;
	const off_t offset = offsetof(typeof(*real_mode), hardware_subarch);
	char *debugfs_mnt;
	char filename[PATH_MAX];

	debugfs_mnt = find_mnt_by_fsname("debugfs");
	if (!debugfs_mnt)
		return;
	snprintf(filename, PATH_MAX, "%s/%s", debugfs_mnt, "boot_params/data");
	filename[PATH_MAX-1] = 0;
	free(debugfs_mnt);

	data_file = open(filename, O_RDONLY);
	if (data_file < 0)
		return;
	if (lseek(data_file, offset, SEEK_SET) < 0)
		goto close;
	read(data_file, &real_mode->hardware_subarch, sizeof(uint32_t));
close:
	close(data_file);
}

void setup_linux_system_parameters(struct kexec_info *info,
				   struct x86_linux_param_header *real_mode)
{
	/* Fill in information the BIOS would usually provide */
	struct memory_range *range;
	int i, ranges;

	/* get subarch from running kernel */
	setup_subarch(real_mode);
	
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

	range = info->memory_range;
	ranges = info->memory_ranges;
	if (ranges > E820MAX) {
		if (!(kexec_flags & KEXEC_ON_CRASH))
			/*
			 * this e820 not used for capture kernel, see
			 * do_bzImage_load()
			 */
			fprintf(stderr,
				"Too many memory ranges, truncating...\n");
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

	/* fill the EDD information */
	setup_edd_info(real_mode);
}
