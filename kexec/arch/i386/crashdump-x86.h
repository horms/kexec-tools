#ifndef CRASHDUMP_X86_H
#define CRASHDUMP_X86_H

struct kexec_info;
int load_crashdump_segments(struct kexec_info *info, char *mod_cmdline,
				unsigned long max_addr, unsigned long min_base);

#define PAGE_OFFSET	0xc0000000
#define __pa(x)		((unsigned long)(x)-PAGE_OFFSET)

#define __VMALLOC_RESERVE       (128 << 20)
#define MAXMEM                  (-PAGE_OFFSET-__VMALLOC_RESERVE)

#define CRASH_MAX_MEMMAP_NR	(KEXEC_MAX_SEGMENTS + 1)
#define CRASH_MAX_MEMORY_RANGES	(MAX_MEMORY_RANGES + 2)

/* Backup Region, First 640K of System RAM. */
#define BACKUP_SRC_START	0x00000000
#define BACKUP_SRC_END		0x0009ffff
#define BACKUP_SRC_SIZE	(BACKUP_SRC_END - BACKUP_SRC_START + 1)

#endif /* CRASHDUMP_X86_H */
