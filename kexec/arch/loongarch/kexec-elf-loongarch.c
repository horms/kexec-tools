/*
 * kexec-elf-loongarch.c - kexec Elf loader for loongarch
 *
 * Copyright (C) 2022 Loongson Technology Corporation Limited.
 *   Youling Tang <tangyouling@loongson.cn>
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
*/

#define _GNU_SOURCE

#include <limits.h>
#include <errno.h>
#include <elf.h>
#include <stdbool.h>

#include "kexec.h"
#include "kexec-elf.h"
#include "kexec-syscall.h"
#include "crashdump-loongarch.h"
#include "kexec-loongarch.h"
#include "arch/options.h"

off_t initrd_base, initrd_size;

int elf_loongarch_probe(const char *kernel_buf, off_t kernel_size)
{
	struct mem_ehdr ehdr;
	int result;

	result = build_elf_exec_info(kernel_buf, kernel_size, &ehdr, 0);
	if (result < 0) {
		dbgprintf("%s: Not an ELF executable.\n", __func__);
		goto out;
	}

	/* Verify the architecuture specific bits. */
	if (ehdr.e_machine != EM_LOONGARCH) {
		dbgprintf("%s: Not an LoongArch ELF executable.\n", __func__);
		result = -1;
		goto out;
	}

	result = 0;
out:
	free_elf_info(&ehdr);
	return result;
}

/*
 * To determine whether it is a relocatable kernel based on the ".la_abs "section,
 * the CRASH_DUMP feature depends on CONFIG_RELOCATABLE in LoongArch.
 */
static bool laabs_section(const struct mem_ehdr *ehdr)
{
	struct mem_shdr *shdr, *shdr_end;
	unsigned char *strtab;

	strtab = (unsigned char *)ehdr->e_shdr[ehdr->e_shstrndx].sh_data;
	shdr_end = &ehdr->e_shdr[ehdr->e_shnum];
	for (shdr = ehdr->e_shdr; shdr != shdr_end; shdr++) {
		if (shdr->sh_size &&
			strcmp((char *)&strtab[shdr->sh_name], ".la_abs") == 0) {
			return true;
		}
	}

	return false;
}

int elf_loongarch_load(int argc, char **argv, const char *kernel_buf,
	off_t kernel_size, struct kexec_info *info)
{
	unsigned long kernel_segment;
	struct mem_ehdr ehdr;
	int result;
	int i;

	result = build_elf_exec_info(kernel_buf, kernel_size, &ehdr, 0);

	if (result < 0) {
		dbgprintf("%s: build_elf_exec_info failed\n", __func__);
		goto exit;
	}

	if (info->kexec_flags & KEXEC_ON_CRASH) {
		bool is_relocatable_kernel = laabs_section(&ehdr);
		if (!is_relocatable_kernel) {
			dbgprintf("%s: The non-relocation kernel cannot be loaded, "
				   "CONFIG_RELOCATABLE needs to be enabled\n", __func__);
			result = EFAILED;
			goto exit;
		}
	}

	for (i = 0; i < ehdr.e_phnum; i++) {
		struct mem_phdr *phdr = &ehdr.e_phdr[i];

		if (phdr->p_type != PT_LOAD)
			continue;

		loongarch_mem.text_offset = virt_to_phys(phdr->p_paddr);
		loongarch_mem.image_size = _ALIGN_UP(phdr->p_memsz, KiB(64));
		break;
	}

	if (i == ehdr.e_phnum) {
		dbgprintf("%s: Valid loongarch phdr not found\n", __func__);
		result = EFAILED;
		goto exit;
	}

	kernel_segment = loongarch_locate_kernel_segment(info);

	if (kernel_segment == ULONG_MAX) {
		dbgprintf("%s: Kernel segment is not allocated\n", __func__);
		result = EFAILED;
		goto exit;
	}

	dbgprintf("%s: kernel_segment: %016lx\n", __func__, kernel_segment);
	dbgprintf("%s: image_size:     %016lx\n", __func__,
		 loongarch_mem.image_size);
	dbgprintf("%s: text_offset:    %016lx\n", __func__,
		loongarch_mem.text_offset);
	dbgprintf("%s: phys_offset:    %016lx\n", __func__,
		loongarch_mem.phys_offset);
	dbgprintf("%s: PE format:      no\n", __func__);

	/* create and initialize elf core header segment */
	if (info->kexec_flags & KEXEC_ON_CRASH) {
		result = load_crashdump_segments(info);
		if (result) {
			dbgprintf("%s: Creating eflcorehdr failed.\n",
								__func__);
			goto exit;
		}
	}

	/* load the kernel */
	if (info->kexec_flags & KEXEC_ON_CRASH)
		/*
		 * offset addresses in elf header in order to load
		 * vmlinux (elf_exec) into crash kernel's memory.
		 */
		fixup_elf_addrs(&ehdr);

	info->entry = (void *)virt_to_phys(ehdr.e_entry);

	result = elf_exec_load(&ehdr, info);

	if (result) {
		dbgprintf("%s: elf_exec_load failed\n", __func__);
		goto exit;
	}

	/* load additional data */
	result = loongarch_load_other_segments(info, kernel_segment + loongarch_mem.image_size);

exit:
	free_elf_info(&ehdr);
	if (result)
		fprintf(stderr, "kexec: Bad elf image file, load failed.\n");
	return result;
}

void elf_loongarch_usage(void)
{
	printf(
"     An LoongArch ELF image, little endian.\n"
"     Typically vmlinux or a stripped version of vmlinux.\n\n");
}
