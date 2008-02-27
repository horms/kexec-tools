/*
 * kexec-mipsel.c - kexec for mips
 * Copyright (C) 2007 Francesco Chiechi, Alessandro Rubini
 * Copyright (C) 2007 Tvblob s.r.l.
 *
 * derived from ../ppc/kexec-mipsel.c
 * Copyright (C) 2004, 2005 Albert Herranz
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <sys/utsname.h>
#include "../../kexec.h"
#include "../../kexec-syscall.h"
#include "kexec-mipsel.h"
#include <arch/options.h>

#define MAX_MEMORY_RANGES  64
#define MAX_LINE          160
static struct memory_range memory_range[MAX_MEMORY_RANGES];

/* Return a sorted list of memory ranges. */
int get_memory_ranges(struct memory_range **range, int *ranges, unsigned long kexec_flags)
{
	int memory_ranges = 0;

#if 1
	/* this is valid for gemini2 platform based on tx4938
	 * in our case, /proc/iomem doesn't report ram space
	 */
	 memory_range[memory_ranges].start = 0x00000000;
	 memory_range[memory_ranges].end = 0x04000000;
	 memory_range[memory_ranges].type = RANGE_RAM;
	 memory_ranges++;
#else
#error Please, fix this for your platform
	const char iomem[] = "/proc/iomem";
	char line[MAX_LINE];
	FILE *fp;
	unsigned long long start, end;
	char *str;
	int type, consumed, count;

	fp = fopen(iomem, "r");
	if (!fp) {
		fprintf(stderr, "Cannot open %s: %s\n", iomem, strerror(errno));
		return -1;
	}
	while (fgets(line, sizeof(line), fp) != 0) {
		if (memory_ranges >= MAX_MEMORY_RANGES)
			break;
		count = sscanf(line, "%Lx-%Lx : %n", &start, &end, &consumed);
		if (count != 2)
			continue;
		str = line + consumed;
		end = end + 1;
#if 0
		printf("%016Lx-%016Lx : %s\n", start, end, str);
#endif
		if (memcmp(str, "System RAM\n", 11) == 0) {
			type = RANGE_RAM;
		} else if (memcmp(str, "reserved\n", 9) == 0) {
			type = RANGE_RESERVED;
		} else if (memcmp(str, "ACPI Tables\n", 12) == 0) {
			type = RANGE_ACPI;
		} else if (memcmp(str, "ACPI Non-volatile Storage\n", 26) == 0) {
			type = RANGE_ACPI_NVS;
		} else {
			continue;
		}
		memory_range[memory_ranges].start = start;
		memory_range[memory_ranges].end = end;
		memory_range[memory_ranges].type = type;
#if 0
		printf("%016Lx-%016Lx : %x\n", start, end, type);
#endif
		memory_ranges++;
	}
	fclose(fp);
#endif

	*range = memory_range;
	*ranges = memory_ranges;
	return 0;
}

struct file_type file_type[] = {
	{"elf-mipsel", elf_mipsel_probe, elf_mipsel_load, elf_mipsel_usage},
};
int file_types = sizeof(file_type) / sizeof(file_type[0]);

void arch_usage(void)
{
}

int arch_process_options(int argc, char **argv)
{
	static const struct option options[] = {
		KEXEC_ARCH_OPTIONS
		{ 0,                    0, NULL, 0 },
	};
	static const char short_options[] = KEXEC_ARCH_OPT_STR;
	int opt;

	opterr = 0; /* Don't complain about unrecognized options here */
	while((opt = getopt_long(argc, argv, short_options, options, 0)) != -1) {
		switch(opt) {
		default:
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
	 if (strcmp(utsname.machine, "mips") == 0)
	 {
		 /* For compatibility with older patches
		  * use KEXEC_ARCH_DEFAULT instead of KEXEC_ARCH_MIPS here.
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
}

/*
 * Adding a dummy function, so that build on mipsel will not break.
 * Need to implement the actual checking code
 */
int is_crashkernel_mem_reserved(void)
{
	return 1;
}

unsigned long virt_to_phys(unsigned long addr)
{
	return addr - 0x80000000;
}

/*
 * add_segment() should convert base to a physical address on mipsel,
 * while the default is just to work with base as is */
void add_segment(struct kexec_info *info, const void *buf, size_t bufsz,
		 unsigned long base, size_t memsz)
{
	add_segment_phys_virt(info, buf, bufsz, base, memsz, 1);
}

/*
 * add_buffer() should convert base to a physical address on mipsel,
 * while the default is just to work with base as is */
unsigned long add_buffer(struct kexec_info *info, const void *buf,
			 unsigned long bufsz, unsigned long memsz,
			 unsigned long buf_align, unsigned long buf_min,
			 unsigned long buf_max, int buf_end)
{
	return add_buffer_phys_virt(info, buf, bufsz, memsz, buf_align,
				    buf_min, buf_max, buf_end, 1);
}

