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
#include <sys/utsname.h>
#include "../../kexec.h"
#include "../../kexec-syscall.h"
#include "kexec-sh.h"
#include <arch/options.h>

#define MAX_MEMORY_RANGES 64
#define MAX_LINE 160
static struct memory_range memory_range[MAX_MEMORY_RANGES];

/* Return a sorted list of available memory ranges. */
int get_memory_ranges(struct memory_range **range, int *ranges,
		      unsigned long kexec_flags)
{
	int memory_ranges;

	memory_ranges = 0;
	memory_range[memory_ranges].start = 0x08000000;
	memory_range[memory_ranges].end   = 0x10000000;
	memory_range[memory_ranges].type  = RANGE_RAM;
	memory_ranges++;
	*range = memory_range;
	*ranges = memory_ranges;
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

static struct {
} arch_options = {
};
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
	if (	(strcmp(utsname.machine, "sh3") == 0) ||
		(strcmp(utsname.machine, "sh4") == 0) ||
		(strcmp(utsname.machine, "sh4a") == 0))
	{
		/*
		 * For compatibility with older patches
		 * use KEXEC_ARCH_DEFAULT instead of KEXEC_ARCH_SH here.
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
	uint64_t start, end;

	return parse_iomem_single("Crash kernel\n", &start, &end) == 0 ?
				  (start != end) : 0;
}

