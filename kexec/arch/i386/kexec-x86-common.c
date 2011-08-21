/*
 * kexec: Linux boots Linux
 *
 * Copyright (C) 2003-2005  Eric Biederman (ebiederm@xmission.com)
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

#define _XOPEN_SOURCE	600
#define _BSD_SOURCE

#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../../kexec.h"
#include "../../kexec-syscall.h"
#include "../../firmware_memmap.h"
#include "../../crashdump.h"
#include "kexec-x86.h"

#ifdef HAVE_LIBXENCTRL
#ifdef HAVE_XC_GET_MACHINE_MEMORY_MAP
#include <xenctrl.h>
#else
#define __XEN_TOOLS__	1
#include <x86/x86-linux.h>
#include <xen/xen.h>
#include <xen/memory.h>
#include <xen/sys/privcmd.h>
#endif /* HAVE_XC_GET_MACHINE_MEMORY_MAP */
#endif /* HAVE_LIBXENCTRL */

static struct memory_range memory_range[MAX_MEMORY_RANGES];

/**
 * The old /proc/iomem parsing code.
 *
 * @param[out] range pointer that will be set to an array that holds the
 *             memory ranges
 * @param[out] ranges number of ranges valid in @p range
 *
 * @return 0 on success, any other value on failure.
 */
static int get_memory_ranges_proc_iomem(struct memory_range **range, int *ranges)
{
	const char *iomem= proc_iomem();
	int memory_ranges = 0;
	char line[MAX_LINE];
	FILE *fp;
	fp = fopen(iomem, "r");
	if (!fp) {
		fprintf(stderr, "Cannot open %s: %s\n",
			iomem, strerror(errno));
		return -1;
	}
	while(fgets(line, sizeof(line), fp) != 0) {
		unsigned long long start, end;
		char *str;
		int type;
		int consumed;
		int count;
		if (memory_ranges >= MAX_MEMORY_RANGES)
			break;
		count = sscanf(line, "%Lx-%Lx : %n",
			&start, &end, &consumed);
		if (count != 2)
			continue;
		str = line + consumed;
		end = end + 1;
#if 0
		printf("%016Lx-%016Lx : %s",
			start, end, str);
#endif
		if (memcmp(str, "System RAM\n", 11) == 0) {
			type = RANGE_RAM;
		}
		else if (memcmp(str, "reserved\n", 9) == 0) {
			type = RANGE_RESERVED;
		}
		else if (memcmp(str, "ACPI Tables\n", 12) == 0) {
			type = RANGE_ACPI;
		}
		else if (memcmp(str, "ACPI Non-volatile Storage\n", 26) == 0) {
			type = RANGE_ACPI_NVS;
		}
		else {
			continue;
		}
		memory_range[memory_ranges].start = start;
		memory_range[memory_ranges].end = end;
		memory_range[memory_ranges].type = type;
#if 0
		printf("%016Lx-%016Lx : %x\n",
			start, end, type);
#endif
		memory_ranges++;
	}
	fclose(fp);
	*range = memory_range;
	*ranges = memory_ranges;
	return 0;
}

/**
 * Calls the architecture independent get_firmware_memmap_ranges() to parse
 * /sys/firmware/memmap and then do some x86 only modifications.
 *
 * @param[out] range pointer that will be set to an array that holds the
 *             memory ranges
 * @param[out] ranges number of ranges valid in @p range
 *
 * @return 0 on success, any other value on failure.
 */
static int get_memory_ranges_sysfs(struct memory_range **range, int *ranges)
{
	int ret;
	size_t range_number = MAX_MEMORY_RANGES;

	ret = get_firmware_memmap_ranges(memory_range, &range_number);
	if (ret != 0) {
		fprintf(stderr, "Parsing the /sys/firmware memory map failed. "
			"Falling back to /proc/iomem.\n");
		return get_memory_ranges_proc_iomem(range, ranges);
	}

	*range = memory_range;
	*ranges = range_number;

	return 0;
}

#ifdef HAVE_LIBXENCTRL
static unsigned e820_to_kexec_type(uint32_t type)
{
	switch (type) {
		case E820_RAM:
			return RANGE_RAM;
		case E820_ACPI:
			return RANGE_ACPI;
		case E820_NVS:
			return RANGE_ACPI_NVS;
		case E820_RESERVED:
		default:
			return RANGE_RESERVED;
	}
}

/**
 * Memory map detection for Xen.
 *
 * @param[out] range pointer that will be set to an array that holds the
 *             memory ranges
 * @param[out] ranges number of ranges valid in @p range
 *
 * @return 0 on success, any other value on failure.
 */
#ifdef HAVE_XC_GET_MACHINE_MEMORY_MAP
static int get_memory_ranges_xen(struct memory_range **range, int *ranges)
{
	int rc, ret = -1;
	struct e820entry e820entries[MAX_MEMORY_RANGES];
	unsigned int i;
#ifdef XENCTRL_HAS_XC_INTERFACE
	xc_interface *xc;
#else
	int xc;
#endif

#ifdef XENCTRL_HAS_XC_INTERFACE
	xc = xc_interface_open(NULL, NULL, 0);

	if (!xc) {
		fprintf(stderr, "%s: Failed to open Xen control interface\n", __func__);
		goto err;
	}
#else
	xc = xc_interface_open();

	if (xc == -1) {
		fprintf(stderr, "%s: Failed to open Xen control interface\n", __func__);
		goto err;
	}
#endif

	rc = xc_get_machine_memory_map(xc, e820entries, MAX_MEMORY_RANGES);

	if (rc < 0) {
		fprintf(stderr, "%s: xc_get_machine_memory_map: %s\n", __func__, strerror(rc));
		goto err;
	}

	for (i = 0; i < rc; ++i) {
		memory_range[i].start = e820entries[i].addr;
		memory_range[i].end = e820entries[i].addr + e820entries[i].size;
		memory_range[i].type = e820_to_kexec_type(e820entries[i].type);
	}

	qsort(memory_range, rc, sizeof(struct memory_range), compare_ranges);

	*range = memory_range;
	*ranges = rc;

	ret = 0;

err:
	xc_interface_close(xc);

	return ret;
}
#else
static int get_memory_ranges_xen(struct memory_range **range, int *ranges)
{
	int fd, rc, ret = -1;
	privcmd_hypercall_t hypercall;
	struct e820entry *e820entries = NULL;
	struct xen_memory_map *xen_memory_map = NULL;
	unsigned int i;

	fd = open("/proc/xen/privcmd", O_RDWR);

	if (fd == -1) {
		fprintf(stderr, "%s: open(/proc/xen/privcmd): %m\n", __func__);
		goto err;
	}

	rc = posix_memalign((void **)&e820entries, sysconf(_SC_PAGESIZE),
			    sizeof(struct e820entry) * MAX_MEMORY_RANGES);

	if (rc) {
		fprintf(stderr, "%s: posix_memalign(e820entries): %s\n", __func__, strerror(rc));
		e820entries = NULL;
		goto err;
	}

	rc = posix_memalign((void **)&xen_memory_map, sysconf(_SC_PAGESIZE),
			    sizeof(struct xen_memory_map));

	if (rc) {
		fprintf(stderr, "%s: posix_memalign(xen_memory_map): %s\n", __func__, strerror(rc));
		xen_memory_map = NULL;
		goto err;
	}

	if (mlock(e820entries, sizeof(struct e820entry) * MAX_MEMORY_RANGES) == -1) {
		fprintf(stderr, "%s: mlock(e820entries): %m\n", __func__);
		goto err;
	}

	if (mlock(xen_memory_map, sizeof(struct xen_memory_map)) == -1) {
		fprintf(stderr, "%s: mlock(xen_memory_map): %m\n", __func__);
		goto err;
	}

	xen_memory_map->nr_entries = MAX_MEMORY_RANGES;
	set_xen_guest_handle(xen_memory_map->buffer, e820entries);

	hypercall.op = __HYPERVISOR_memory_op;
	hypercall.arg[0] = XENMEM_machine_memory_map;
	hypercall.arg[1] = (__u64)xen_memory_map;

	rc = ioctl(fd, IOCTL_PRIVCMD_HYPERCALL, &hypercall);

	if (rc == -1) {
		fprintf(stderr, "%s: ioctl(IOCTL_PRIVCMD_HYPERCALL): %m\n", __func__);
		goto err;
	}

	for (i = 0; i < xen_memory_map->nr_entries; ++i) {
		memory_range[i].start = e820entries[i].addr;
		memory_range[i].end = e820entries[i].addr + e820entries[i].size;
		memory_range[i].type = e820_to_kexec_type(e820entries[i].type);
	}

	qsort(memory_range, xen_memory_map->nr_entries, sizeof(struct memory_range), compare_ranges);

	*range = memory_range;
	*ranges = xen_memory_map->nr_entries;

	ret = 0;

err:
	munlock(xen_memory_map, sizeof(struct xen_memory_map));
	munlock(e820entries, sizeof(struct e820entry) * MAX_MEMORY_RANGES);
	free(xen_memory_map);
	free(e820entries);
	close(fd);

	return ret;
}
#endif /* HAVE_XC_GET_MACHINE_MEMORY_MAP */
#else
static int get_memory_ranges_xen(struct memory_range **range, int *ranges)
{
	return 0;
}
#endif /* HAVE_LIBXENCTRL */

static void remove_range(struct memory_range *range, int nr_ranges, int index)
{
	int i, j;

	for (i = index; i < (nr_ranges-1); i++) {
		j = i+1;
		range[i] = range[j];
	}
}

/**
 * Verifies and corrects any overlapping ranges.
 * The ranges array is assumed to be sorted already.
 *
 * @param[out] range pointer that will be set to an array that holds the
 *             memory ranges
 * @param[out] ranges number of ranges valid in @p range
 *
 * @return 0 on success, any other value on failure.
 */
static int fixup_memory_ranges(struct memory_range **range, int *ranges)
{
	int i;
	int j;
	int change_made;
	int nr_ranges = *ranges;
	struct memory_range *rp = *range;

again:
	change_made = 0;
	for (i = 0; i < (nr_ranges-1); i++) {
		j = i+1;
		if (rp[i].start > rp[j].start) {
			fprintf(stderr, "memory out of order!!\n");
			return 1;
		}

		if (rp[i].type != rp[j].type)
			continue;

		if (rp[i].start == rp[j].start) {
			if (rp[i].end >= rp[j].end) {
				remove_range(rp, nr_ranges, j);
				nr_ranges--;
				change_made++;
			} else {
				remove_range(rp, nr_ranges, i);
				nr_ranges--;
				change_made++;
			}
		} else {
			if (rp[i].end > rp[j].start) {
				if (rp[i].end < rp[j].end) {
					rp[j].start = rp[i].end;
					change_made++;
				} else if (rp[i].end >= rp[j].end) {
					remove_range(rp, nr_ranges, j);
					nr_ranges--;
					change_made++;
				}
			}
		}
	}

	/* fixing/removing an entry may make it wrong relative to the next */
	if (change_made)
		goto again;

	*ranges = nr_ranges;
	return 0;
}

/**
 * Detect the add_efi_memmap kernel parameter.
 *
 * On some EFI-based systems, the e820 map is empty, or does not contain a
 * complete memory map. The add_efi_memmap parameter adds these entries to
 * the kernel's memory map, but does not add them under sysfs, which causes
 * kexec to fail in a way similar to how it does not work on Xen.
 *
 * @return 1 if parameter is present, 0 if not or if an error occurs.
 */
int efi_map_added( void ) {
	char buf[512], *res;
	FILE *fp = fopen( "/proc/cmdline", "r" );
	if( fp ) {
		res = fgets( buf, 512, fp );
		fclose( fp );
		return strstr( buf, "add_efi_memmap" ) != NULL;
	} else {
		return 0;
	}
}

/**
 * Return a sorted list of memory ranges.
 *
 * If we have the /sys/firmware/memmap interface, then use that. If not,
 * or if parsing of that fails, use /proc/iomem as fallback.
 *
 * @param[out] range pointer that will be set to an array that holds the
 *             memory ranges
 * @param[out] ranges number of ranges valid in @p range
 * @param[in]  kexec_flags the kexec_flags to determine if we load a normal
 *             or a crashdump kernel
 *
 * @return 0 on success, any other value on failure.
 */
int get_memory_ranges(struct memory_range **range, int *ranges,
		      unsigned long kexec_flags)
{
	int ret, i;

	if (!efi_map_added() && !xen_present() && have_sys_firmware_memmap()) {
		ret = get_memory_ranges_sysfs(range, ranges);
		if (!ret)
			ret = fixup_memory_ranges(range, ranges);
	} else if (xen_present()) {
		ret = get_memory_ranges_xen(range, ranges);
		if (!ret)
			ret = fixup_memory_ranges(range, ranges);
	} else
		ret = get_memory_ranges_proc_iomem(range, ranges);

	/*
	 * get_memory_ranges_sysfs(), get_memory_ranges_proc_iomem() and
	 * get_memory_ranges_xen() have already printed an error message,
	 * so fail silently here.
	 */
	if (ret != 0)
		return ret;

	/* Don't report the interrupt table as ram */
	for (i = 0; i < *ranges; i++) {
		if ((*range)[i].type == RANGE_RAM &&
				((*range)[i].start < 0x100)) {
			(*range)[i].start = 0x100;
			break;
		}
	}

	/*
	 * Redefine the memory region boundaries if kernel
	 * exports the limits and if it is panic kernel.
	 * Override user values only if kernel exported values are
	 * subset of user defined values.
	 */
	if ((kexec_flags & KEXEC_ON_CRASH) &&
	    !(kexec_flags & KEXEC_PRESERVE_CONTEXT)) {
		uint64_t start, end;

		ret = parse_iomem_single("Crash kernel\n", &start, &end);
		if (ret != 0) {
			fprintf(stderr, "parse_iomem_single failed.\n");
			return -1;
		}

		if (start > mem_min)
			mem_min = start;
		if (end < mem_max)
			mem_max = end;
	}

	/* just set 0 to 1 to enable printing for debugging */
#if 0
	{
		int i;
		printf("MEMORY RANGES\n");
		for (i = 0; i < *ranges; i++) {
			printf("%016Lx-%016Lx (%d)\n", (*range)[i].start,
				(*range)[i].end, (*range)[i].type);
		}
	}
#endif

	return ret;
}


