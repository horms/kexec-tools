#ifndef CRASHDUMP_X86_64_H
#define CRASHDUMP_X86_64_H

#include "../../kexec.h"

int load_crashdump_segments(struct kexec_info *info, char *mod_cmdline,
				unsigned long max_addr, unsigned long min_base);

#define __START_KERNEL_map      0xffffffff80000000UL

extern unsigned long page_offset;

#define __pa(x)                 (((unsigned long)(x)>=__START_KERNEL_map)?(unsigned long)(x) - (unsigned long)__START_KERNEL_map:(unsigned long)(x) - page_offset)

#define MAXMEM           0x3fffffffffffUL

/* Kernel text size */
#define KERNEL_TEXT_SIZE  (512UL*1024*1024)

#define CRASH_MAX_MEMMAP_NR	(KEXEC_MAX_SEGMENTS + 1)
#define CRASH_MAX_MEMORY_RANGES	(MAX_MEMORY_RANGES + 2)

/* Backup Region, First 640K of System RAM. */
#define BACKUP_SRC_START	0x00000000
#define BACKUP_SRC_END		0x0009ffff
#define BACKUP_SRC_SIZE		(BACKUP_SRC_END - BACKUP_SRC_START + 1)

#endif /* CRASHDUMP_X86_64_H */
