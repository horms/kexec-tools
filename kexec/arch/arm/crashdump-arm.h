#ifndef CRASHDUMP_ARM_H
#define CRASHDUMP_ARM_H

#ifdef __cplusplus
extern "C" {
#endif

#define COMMAND_LINE_SIZE	1024
#define PAGE_OFFSET		0xc0000000
#define CRASH_MAX_MEMORY_RANGES	32

extern struct memory_ranges usablemem_rgns;

struct kexec_info;

extern unsigned long phys_offset;
extern int load_crashdump_segments(struct kexec_info *, char *);

#ifdef __cplusplus
}
#endif

#endif /* CRASHDUMP_ARM_H */
