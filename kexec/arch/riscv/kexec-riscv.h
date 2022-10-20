/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 FORTH-ICS/CARV
 *              Nick Kossifidis <mick@ics.forth.gr>
 */

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
int load_extra_segments(struct kexec_info *info, uint64_t kernel_base,
			uint64_t kernel_size, uint64_t max_addr);

int elf_riscv_probe(const char *buf, off_t len);
void elf_riscv_usage(void);
int elf_riscv_load(int argc, char **argv, const char *buf, off_t len,
		   struct kexec_info *info);
