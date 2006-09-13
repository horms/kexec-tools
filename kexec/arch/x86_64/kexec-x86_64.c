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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/utsname.h>
#include "../../kexec.h"
#include "../../kexec-elf.h"
#include "../../kexec-syscall.h"
#include "kexec-x86_64.h"
#include "crashdump-x86_64.h"
#include <arch/options.h>

#define MAX_MEMORY_RANGES 64
static struct memory_range memory_range[MAX_MEMORY_RANGES];

/* Return a sorted list of memory ranges. */
int get_memory_ranges(struct memory_range **range, int *ranges,
					unsigned long kexec_flags)
{
	const char iomem[]= "/proc/iomem";
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
		else if (memcmp(str, "Crash kernel\n", 13) == 0) {
			/* Redefine the memory region boundaries if kernel
			 * exports the limits and if it is panic kernel.
			 * Override user values only if kernel exported
			 * values are subset of user defined values.
			 */
			if (kexec_flags & KEXEC_ON_CRASH) {
				if (start > mem_min)
					mem_min = start;
				if (end < mem_max)
					mem_max = end;
			}
			continue;
		}
		else {
			continue;
		}
		/* Don't report the interrupt table as ram */
		if (type == RANGE_RAM && (start < 0x100)) {
			start = 0x100;
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

struct file_type file_type[] = {
	{ "elf-x86_64", elf_x86_64_probe, elf_x86_64_load, elf_x86_64_usage },
	{ "multiboot-x86", multiboot_x86_probe, multiboot_x86_load, 
	  multiboot_x86_usage },
	{ "elf-x86", elf_x86_probe, elf_x86_load, elf_x86_usage },
	{ "bzImage", bzImage_probe, bzImage_load, bzImage_usage },
	{ "beoboot-x86", beoboot_probe, beoboot_load, beoboot_usage },
	{ "nbi-x86", nbi_probe, nbi_load, nbi_usage },
};
int file_types = sizeof(file_type)/sizeof(file_type[0]);


void arch_usage(void)
{
	printf(
		"     --reset-vga               Attempt to reset a standard vga device\n"
		"     --serial=<port>           Specify the serial port for debug output\n"
		"     --serial-baud=<buad_rate> Specify the serial port baud rate\n"
		"     --console-vga             Enable the vga console\n"
		"     --console-serial          Enable the serial console\n"
		);
}

static struct {
	uint8_t  reset_vga;
	uint16_t serial_base;
	uint32_t serial_baud;
	uint8_t  console_vga;
	uint8_t  console_serial;
	int core_header_type;
} arch_options = {
	.reset_vga   = 0,
	.serial_base = 0x3f8,
	.serial_baud = 0,
	.console_vga = 0,
	.console_serial = 0,
	.core_header_type = CORE_TYPE_ELF64,
};

int arch_process_options(int argc, char **argv)
{
	static const struct option options[] = {
		KEXEC_ARCH_OPTIONS
		{ 0, 			0, NULL, 0 },
	};
	static const char short_options[] = KEXEC_ARCH_OPT_STR;
	int opt;
	unsigned long value;
	char *end;

	opterr = 0; /* Don't complain about unrecognized options here */
	while((opt = getopt_long(argc, argv, short_options, options, 0)) != -1) {
		switch(opt) {
		default:
			break;
		case OPT_RESET_VGA:
			arch_options.reset_vga = 1;
			break;
		case OPT_CONSOLE_VGA:
			arch_options.console_vga = 1;
			break;
		case OPT_CONSOLE_SERIAL:
			arch_options.console_serial = 1;
			break;
		case OPT_SERIAL:
			value = ULONG_MAX;
			if (strcmp(optarg, "ttyS0") == 0) {
				value = 0x3f8;
			}
			else if (strcmp(optarg, "ttyS1") == 0) {
				value = 0x2f8;
			}
			else if (strncmp(optarg, "0x", 2) == 0) {
				value = strtoul(optarg +2, &end, 16);
				if (*end != '\0') {
					value = ULONG_MAX;
				}
			}
			if (value >= 65536) {
				fprintf(stderr, "Bad serial port base '%s'\n", 
					optarg);
				usage();
				return -1;
				
			}
			arch_options.serial_base = value;
			break;
		case OPT_SERIAL_BAUD:
			value = strtoul(optarg, &end, 0);
			if ((value > 115200) || ((115200 %value) != 0) || 
				(value < 9600) || (*end)) 
			{
				fprintf(stderr, "Bad serial port baud rate '%s'\n",
					optarg);
				usage();
				return -1;
				
			}
			arch_options.serial_baud = value;
			break;
		}
	}
	/* Reset getopt for the next pass; called in other source modules */
	opterr = 1;
	optind = 1;
	return 0;
}

int arch_compat_trampoline(struct kexec_info *info)
{
	int result;
	struct utsname utsname;
	result = uname(&utsname);
	if (result < 0) {
		fprintf(stderr, "uname failed: %s\n",
			strerror(errno));
		return -1;
	}
	if (strcmp(utsname.machine, "x86_64") == 0)
	{
		/* For compatibility with older patches 
		 * use KEXEC_ARCH_DEFAULT instead of KEXEC_ARCH_X86_64 here.
		 */
		info->kexec_flags |= KEXEC_ARCH_DEFAULT;
	}
	else {
		fprintf(stderr, "Unsupported machine type: %s\n",
			utsname.machine);
		return -1;
	}
	return 0;
}

void arch_update_purgatory(struct kexec_info *info)
{
	uint8_t panic_kernel = 0;

	elf_rel_set_symbol(&info->rhdr, "reset_vga",
		&arch_options.reset_vga, sizeof(arch_options.reset_vga));
	elf_rel_set_symbol(&info->rhdr, "serial_base", 
		&arch_options.serial_base, sizeof(arch_options.serial_base));
	elf_rel_set_symbol(&info->rhdr, "serial_baud", 
		&arch_options.serial_baud, sizeof(arch_options.serial_baud));
	elf_rel_set_symbol(&info->rhdr, "console_vga", 
		&arch_options.console_vga, sizeof(arch_options.console_vga));
	elf_rel_set_symbol(&info->rhdr, "console_serial", 
		&arch_options.console_serial, sizeof(arch_options.console_serial));

	if (info->kexec_flags & KEXEC_ON_CRASH) {
		panic_kernel = 1;
		elf_rel_set_symbol(&info->rhdr, "backup_start",
					&info->backup_start, sizeof(info->backup_start));
	}
	elf_rel_set_symbol(&info->rhdr, "panic_kernel",
				&panic_kernel, sizeof(panic_kernel));
}
