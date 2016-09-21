/*
 * ARM64 kexec.
 */

#if !defined(KEXEC_ARM64_H)
#define KEXEC_ARM64_H

#include <stdbool.h>
#include <sys/types.h>

#include "image-header.h"
#include "kexec.h"

#define KEXEC_SEGMENT_MAX 16

#define BOOT_BLOCK_VERSION 17
#define BOOT_BLOCK_LAST_COMP_VERSION 16
#define COMMAND_LINE_SIZE 512

#define KiB(x) ((x) * 1024UL)
#define MiB(x) (KiB(x) * 1024UL)
#define GiB(x) (MiB(x) * 1024UL)

int elf_arm64_probe(const char *kernel_buf, off_t kernel_size);
int elf_arm64_load(int argc, char **argv, const char *kernel_buf,
	off_t kernel_size, struct kexec_info *info);
void elf_arm64_usage(void);

int image_arm64_probe(const char *kernel_buf, off_t kernel_size);
int image_arm64_load(int argc, char **argv, const char *kernel_buf,
	off_t kernel_size, struct kexec_info *info);
void image_arm64_usage(void);

off_t initrd_base;
off_t initrd_size;

/**
 * struct arm64_mem - Memory layout info.
 */

struct arm64_mem {
	uint64_t phys_offset;
	uint64_t text_offset;
	uint64_t image_size;
	uint64_t vp_offset;
};

#define arm64_mem_ngv UINT64_MAX
struct arm64_mem arm64_mem;

uint64_t get_phys_offset(void);
uint64_t get_vp_offset(void);

static inline void reset_vp_offset(void)
{
	arm64_mem.vp_offset = arm64_mem_ngv;
}

static inline void set_phys_offset(uint64_t v)
{
	if (arm64_mem.phys_offset == arm64_mem_ngv
		|| v < arm64_mem.phys_offset)
		arm64_mem.phys_offset = v;
}

int arm64_process_image_header(const struct arm64_image_header *h);
unsigned long arm64_locate_kernel_segment(struct kexec_info *info);
int arm64_load_other_segments(struct kexec_info *info,
	unsigned long image_base);

#endif
