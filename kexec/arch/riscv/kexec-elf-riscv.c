/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 FORTH-ICS/CARV
 *              Nick Kossifidis <mick@ics.forth.gr>
 */

#include "kexec.h"
#include "dt-ops.h"		/* For dtb_set/clear_initrd() */
#include <elf.h>		/* For ELF header handling */
#include <errno.h>		/* For EFBIG/EINVAL */
#include <unistd.h>		/* For getpagesize() */
#include "kexec-syscall.h"	/* For KEXEC_ON_CRASH */
#include "kexec-riscv.h"

/**************\
* ENTRY POINTS *
\**************/

int elf_riscv_probe(const char *buf, off_t len)
{
	struct mem_ehdr ehdr = {0};
	int ret = 0;

	ret = build_elf_exec_info(buf, len, &ehdr, 0);
	if (ret < 0)
		goto cleanup;

	if (ehdr.e_machine != EM_RISCV) {
		fprintf(stderr, "Not for this architecture.\n");
		ret = -EINVAL;
		goto cleanup;
	}

	ret = 0;

 cleanup:
	free_elf_info(&ehdr);
	return ret;
}

void elf_riscv_usage(void)
{
}


int elf_riscv_load(int argc, char **argv, const char *buf, off_t len,
		   struct kexec_info *info)
{
	struct mem_ehdr ehdr = {0};
	struct mem_phdr *phdr = NULL;
	off_t new_base_addr = 0;
	off_t kernel_size = 0;
	off_t page_size = getpagesize();
	off_t max_addr = 0;
	off_t old_base_addr = 0;
	off_t old_start_addr = 0;
	int i = 0;
	int ret = 0;

	if (info->file_mode) {
		return prepare_kexec_file_options(info);
	}

	/* Parse the ELF file */
	ret = build_elf_exec_info(buf, len, &ehdr, 0);
	if (ret < 0) {
		fprintf(stderr, "ELF exec parse failed\n");
		return -EINVAL;
	}

	max_addr = elf_max_addr(&ehdr);
	old_base_addr = max_addr;
	old_start_addr = max_addr;

	/*
	 * Get the memory footprint, base physical
	 * and start address of the ELF image
	 */
	for (i = 0; i < ehdr.e_phnum; i++) {
		phdr = &ehdr.e_phdr[i];
		if (phdr->p_type != PT_LOAD)
			continue;

		/*
		 * Note: According to ELF spec the loadable regions
		 * are sorted on p_vaddr, not p_paddr.
		 */
		if (old_base_addr > phdr->p_paddr)
			old_base_addr = phdr->p_paddr;

		if (phdr->p_vaddr == ehdr.e_entry ||
		    phdr->p_paddr == ehdr.e_entry)
			old_start_addr = phdr->p_paddr;

		kernel_size += _ALIGN_UP(phdr->p_memsz, page_size);
	}

	if (old_base_addr == max_addr || kernel_size == 0) {
		fprintf(stderr, "No loadable segments present on the "
				"provided ELF image\n");
		return -EINVAL;
	}

	if (old_start_addr == max_addr) {
		fprintf(stderr, "Could not find the entry point address of "
				"provided ELF image\n");
		return -EINVAL;
	}

	dbgprintf("Got ELF with total memsz %luKB\n"
		  "Base paddr: 0x%lX, start_addr: 0x%lX\n",
		  kernel_size / 1024, old_base_addr, old_start_addr);

	/* Get a continuous physical region that can hold the kernel */
	ret = riscv_find_pbase(info, &new_base_addr, kernel_size, KERNEL_ALIGN);
	if (ret < 0) {
		fprintf(stderr, "Could not find a memory region for the "
				"provided ELF image\n");
		return ret;
	}

	dbgprintf("New base paddr for the ELF: 0x%lX\n", new_base_addr);

	/* Re-set the base physical address of the ELF */
	for (i = 0; i < ehdr.e_phnum; i++) {
		phdr = &ehdr.e_phdr[i];
		if (phdr->p_type != PT_LOAD)
			continue;

		phdr->p_paddr -= old_base_addr;
		phdr->p_paddr += new_base_addr;
	}

	/* Re-set the entry point address */
	ehdr.e_entry = (old_start_addr - old_base_addr) + new_base_addr;
	info->entry = (void *) ehdr.e_entry;
	dbgprintf("New entry point for the ELF: 0x%llX\n", ehdr.e_entry);


	/* Load the ELF executable */
	ret = elf_exec_load(&ehdr, info);
	if (ret < 0) {
		fprintf(stderr, "ELF exec load failed\n");
		return ret;
	}

	ret = load_extra_segments(info, new_base_addr,
				  kernel_size, max_addr);
	return ret;
}


/*******\
* STUBS *
\*******/

int machine_verify_elf_rel(struct mem_ehdr *ehdr)
{
	if (ehdr->ei_data != ELFDATA2LSB)
		return 0;
#if __riscv_xlen == 64
	if (ehdr->ei_class != ELFCLASS64)
#else
	if (ehdr->ei_class != ELFCLASS32)
#endif
		return 0;
	if (ehdr->e_machine != EM_RISCV)
		return 0;
	return 1;
}

void machine_apply_elf_rel(struct mem_ehdr *UNUSED(ehdr),
			   struct mem_sym *UNUSED(sym),
			   unsigned long r_type,
			   void *UNUSED(location),
			   unsigned long UNUSED(address),
			   unsigned long UNUSED(value))
{
	switch (r_type) {
	default:
		die("Unknown rela relocation: %lu\n", r_type);
		break;
	}
}
