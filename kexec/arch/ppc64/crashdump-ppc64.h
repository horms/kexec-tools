#ifndef CRASHDUMP_PPC64_H
#define CRASHDUMP_PPC64_H

struct kexec_info;
int load_crashdump_segments(struct kexec_info *info, char *mod_cmdline,
				unsigned long max_addr, unsigned long min_base);
void add_usable_mem_rgns(unsigned long long base, unsigned long long size);

#define PAGE_OFFSET     0xC000000000000000
#define KERNELBASE      PAGE_OFFSET
#define VMALLOCBASE     0xD000000000000000

#define __pa(x)         ((unsigned long)(x)-PAGE_OFFSET)
#define MAXMEM          (-KERNELBASE-VMALLOCBASE)

#define COMMAND_LINE_SIZE       512 /* from kernel */
/* Backup Region, First 64K of System RAM. */
#define BACKUP_SRC_START    0x0000
#define BACKUP_SRC_END      0xffff
#define BACKUP_SRC_SIZE     (BACKUP_SRC_END - BACKUP_SRC_START + 1)

#define KDUMP_BACKUP_LIMIT	BACKUP_SRC_SIZE
#define _ALIGN_UP(addr,size)	(((addr)+((size)-1))&(~((size)-1)))
#define _ALIGN_DOWN(addr,size)	((addr)&(~((size)-1)))

extern uint64_t crash_base;
extern uint64_t crash_size;
extern unsigned int rtas_base;
extern unsigned int rtas_size;

#endif /* CRASHDUMP_PPC64_H */
