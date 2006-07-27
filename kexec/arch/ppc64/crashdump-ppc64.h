#ifndef CRASHDUMP_PPC64_H
#define CRASHDUMP_PPC64_H

void add_usable_mem_rgns(unsigned long long base, unsigned long long size);

#define PAGE_OFFSET      0xC000000000000000
#define KERNELBASE      PAGE_OFFSET
#define VMALLOCBASE     0xD000000000000000

#define __pa(x)         ((unsigned long)(x)-PAGE_OFFSET)

#define MAXMEM                  (-KERNELBASE-VMALLOCBASE)

#define CRASH_MAX_MEMORY_RANGES (MAX_MEMORY_RANGES + 6)

#define COMMAND_LINE_SIZE       512 /* from kernel */
/* Backup Region, First 32K of System RAM. */
#define BACKUP_START    0x0000
#define BACKUP_END      0x8000
#define BACKUP_SIZE     (BACKUP_END - BACKUP_START + 1)

#define KDUMP_BACKUP_LIMIT      0x8000
#define _ALIGN_UP(addr,size)     (((addr)+((size)-1))&(~((size)-1)))
#define _ALIGN_DOWN(addr,size)   ((addr)&(~((size)-1)))
#define PAGE_SIZE      4096

#endif /* CRASHDUMP_PPC64_H */
