/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 FORTH-ICS/CARV
 *              Nick Kossifidis <mick@ics.forth.gr>
 */

/*
 * Kernel should be aligned to the nearest
 * hugepage (2MB for RV64, 4MB for RV32).
 */

#if __riscv_xlen == 64
#define KERNEL_ALIGN 0x200000
#else
#define KERNEL_ALIGN 0x400000
#endif

struct fdt_image {
	char	*buf;
	off_t	size;
};

struct riscv_opts {
	char *cmdline;
	char *fdt_path;
	char *initrd_path;
	uint64_t initrd_start;
	uint64_t initrd_end;
	struct fdt_image *fdt;
};

/* crashdump-riscv.c */
extern struct memory_range elfcorehdr_mem;
int load_elfcorehdr(struct kexec_info *info);

/* kexec-riscv.c */
int prepare_kexec_file_options(struct kexec_info *info);
int load_extra_segments(struct kexec_info *info, uint64_t kernel_base,
			uint64_t kernel_size, uint64_t max_addr);
int riscv_find_pbase(struct kexec_info *info, off_t *addr,
				off_t size, off_t align);

/* kexec-elf-riscv.c */
int elf_riscv_probe(const char *buf, off_t len);
void elf_riscv_usage(void);
int elf_riscv_load(int argc, char **argv, const char *buf, off_t len,
		   struct kexec_info *info);

/* kexec-image-riscv.c */
int image_riscv_probe(const char *buf, off_t len);
void image_riscv_usage(void);
int image_riscv_load(int argc, char **argv, const char *buf, off_t len,
		   struct kexec_info *info);
