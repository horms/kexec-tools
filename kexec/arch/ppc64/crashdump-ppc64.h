#ifndef CRASHDUMP_PPC64_H
#define CRASHDUMP_PPC64_H

#include <stdint.h>
#include <sys/types.h>

struct kexec_info;
int load_crashdump_segments(struct kexec_info *info, char *mod_cmdline,
				uint64_t max_addr, unsigned long min_base);
void add_usable_mem_rgns(unsigned long long base, unsigned long long size);

#define PAGE_OFFSET     0xC000000000000000ULL
#define KERNELBASE      PAGE_OFFSET
#define VMALLOCBASE     0xD000000000000000ULL

#define __pa(x)         ((unsigned long)(x)-PAGE_OFFSET)
#define MAXMEM          (-KERNELBASE-VMALLOCBASE)

#define COMMAND_LINE_SIZE       512 /* from kernel */
/* Backup Region, First 64K of System RAM. */
#define BACKUP_SRC_START    0x0000
#define BACKUP_SRC_END      0xffff
#define BACKUP_SRC_SIZE     (BACKUP_SRC_END - BACKUP_SRC_START + 1)

#define KDUMP_BACKUP_LIMIT	BACKUP_SRC_SIZE

#define KERNEL_RUN_AT_ZERO_MAGIC 0x72756e30	/* "run0" */

extern uint64_t crash_base;
extern uint64_t crash_size;
extern uint64_t memory_limit;
extern unsigned int rtas_base;
extern unsigned int rtas_size;

uint64_t lmb_size;
unsigned int num_of_lmbs;

#define DRCONF_ADDR	0
#define DRCONF_FLAGS	20

#endif /* CRASHDUMP_PPC64_H */
