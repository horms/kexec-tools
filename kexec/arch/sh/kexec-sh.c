/*
 * kexec-sh.c - kexec for the SH
 * Copyright (C) 2004 kogiidena@eggplant.ddo.jp
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "../../kexec.h"
#include "../../kexec-syscall.h"
#include "kexec-sh.h"
#include <arch/options.h>

#define MAX_MEMORY_RANGES 64
static struct memory_range memory_range[MAX_MEMORY_RANGES];

static int kexec_sh_memory_range_callback(void *data, int nr,
					  char *str,
					  unsigned long base,
					  unsigned long length)
{
	if (nr < MAX_MEMORY_RANGES) {
		memory_range[nr].start = base;
		memory_range[nr].end = base + length - 1;
		memory_range[nr].type = RANGE_RAM;
		return 0;
	}

	return 1;
}

/* Return a sorted list of available memory ranges. */
int get_memory_ranges(struct memory_range **range, int *ranges,
		      unsigned long kexec_flags)
{
	int nr;

	nr = kexec_iomem_for_each_line("System RAM\n",
				       kexec_sh_memory_range_callback, NULL);
	*range = memory_range;
	*ranges = nr;
	return 0;
}

/* Supported file types and callbacks */
struct file_type file_type[] = {
       {"zImage-sh", zImage_sh_probe, zImage_sh_load, zImage_sh_usage},
       {"netbsd-sh", netbsd_sh_probe, netbsd_sh_load, netbsd_sh_usage},
};
int file_types = sizeof(file_type) / sizeof(file_type[0]);


void arch_usage(void)
{

  printf(
    " none\n\n"
    "Default options:\n"
    " --append=\"%s\"\n"
    " --empty-zero=0x%08x\n\n"
    " STRING of --appned is set form /proc/cmdline as default.\n"
    " ADDRESS of --empty-zero can be set SHELL environment variable\n"
    " KEXEC_EMPTY_ZERO as default.\n\n"
    " ADDRESS can be get in the following method in your system. \n"
    " 1) \"grep empty_zero /proc/kallsyms\". \n"
    " 2) \"grep empty_zero System.map\". \n"
    " 3) CONFIG_MEMORY_START + CONFIG_ZERO_PAGE_OFFSET in your kernel\n"
    "    config file.\n"
    ,get_append(), (unsigned int) get_empty_zero(NULL));

}

int arch_process_options(int argc, char **argv)
{
	static const struct option options[] = {
		KEXEC_ARCH_OPTIONS
		{ 0, 			0, NULL, 0 },
	};
	static const char short_options[] = KEXEC_ARCH_OPT_STR;
	int opt;

	opterr = 0; /* Don't complain about unrecognized options here */
	while((opt = getopt_long(argc, argv, short_options, options, 0)) != -1) {
		switch(opt) {
		default:
			/* Ignore core options */
			if (opt < OPT_MAX) {
				break;
			}
		case '?':
		        usage();
		  	return -1;
		case OPT_APPEND:
		case OPT_NBSD_HOWTO:
		case OPT_NBSD_MROOT:
		  ;
		}
	}
	/* Reset getopt for the next pass; called in other source modules */
	opterr = 1;
	optind = 1;
	return 0;
}

const struct arch_map_entry arches[] = {
	/* For compatibility with older patches
	 * use KEXEC_ARCH_DEFAULT instead of KEXEC_ARCH_SH here.
	 */
	{ "sh3", KEXEC_ARCH_DEFAULT },
	{ "sh4", KEXEC_ARCH_DEFAULT },
	{ "sh4a", KEXEC_ARCH_DEFAULT },
	{ "sh4al-dsp", KEXEC_ARCH_DEFAULT },
	{ 0 },
};

int arch_compat_trampoline(struct kexec_info *info)
{
	return 0;
}

void arch_update_purgatory(struct kexec_info *info)
{
}


unsigned long get_empty_zero(char *s)
{
        char *env;

	env = getenv("KEXEC_EMPTY_ZERO");

	if(s){
	  env = s;
	}else if(!env){
	  env = "0x0c001000";
	}
	return 0x1fffffff & strtoul(env,(char **)NULL,0);
}

char append_buf[256];

char *get_append(void)
{
        FILE *fp;
        int len;
        if((fp = fopen("/proc/cmdline", "r")) == NULL){
              printf("/proc/cmdline file open error !!\n");
              exit(1);
        }
        fgets(append_buf, 256, fp);
        len = strlen(append_buf);
        append_buf[len-1] = 0;
        fclose(fp);
        return append_buf;
}


int is_crashkernel_mem_reserved(void)
{
	return 0; /* kdump is not supported on this platform (yet) */
}

unsigned long virt_to_phys(unsigned long addr)
{
	unsigned long seg = addr & 0xe0000000;
	if (seg != 0x80000000 && seg != 0xc0000000)
		die("Virtual address %p is not in P1 or P2\n", (void *)addr);

	return addr - seg;
}

/*
 * add_segment() should convert base to a physical address on superh,
 * while the default is just to work with base as is */
void add_segment(struct kexec_info *info, const void *buf, size_t bufsz,
		 unsigned long base, size_t memsz)
{
	add_segment_phys_virt(info, buf, bufsz, base, memsz, 1);
}

/*
 * add_buffer() should convert base to a physical address on superh,
 * while the default is just to work with base as is */
unsigned long add_buffer(struct kexec_info *info, const void *buf,
			 unsigned long bufsz, unsigned long memsz,
			 unsigned long buf_align, unsigned long buf_min,
			 unsigned long buf_max, int buf_end)
{
	return add_buffer_phys_virt(info, buf, bufsz, memsz, buf_align,
				    buf_min, buf_max, buf_end, 1);
}
