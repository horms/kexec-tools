/*
 * kexec: Linux boots Linux
 *
 * Created by: Murali M Chakravarthy (muralim@in.ibm.com)
 * Copyright (C) IBM Corporation, 2005. All rights reserved
 * Heavily borrowed from kexec/arch/i386/crashdump-x86.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation (version 2 of the License).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../../kexec.h"
#include "../../kexec-elf.h"
#include "../../kexec-syscall.h"
#include "kexec-x86_64.h"
#include "crashdump-x86_64.h"
#include <x86/x86-linux.h>

/* Returns the virtual address of start of crash notes buffer for a cpu. */
static int get_crash_notes_section_addr(int cpu, unsigned long long *addr)
{

#define MAX_SYSFS_PATH_LEN	70
	char crash_notes[MAX_SYSFS_PATH_LEN];
	char line[MAX_LINE];
	FILE *fp;
	struct stat cpu_stat;

	sprintf(crash_notes, "/sys/devices/system/cpu");
	if (stat(crash_notes, &cpu_stat)) {
		die("Cannot stat %s: %s\nTry mounting sysfs\n",
				crash_notes, strerror(errno));
	}

	sprintf(crash_notes, "/sys/devices/system/cpu/cpu%d/crash_notes", cpu);
	fp = fopen(crash_notes, "r");
	if (!fp) {
		/* CPU is not physically present.*/
		*addr = 0;
		return -1;
	}

	if (fgets(line, sizeof(line), fp) != 0) {
		int count;
		count = sscanf(line, "%Lx", addr);
		if (count != 1) {
			*addr = 0;
			return -1;
		}
#if 0
		printf("crash_notes addr = %Lx\n", *addr);
#endif
	}
	return 0;
}

/* Prepares the crash memory elf64 headers and stores in supplied buffer. */
static int prepare_crash_memory_elf64_headers(struct kexec_info *info,
						void *buf, unsigned long size)
{
	Elf64_Ehdr *elf;
	Elf64_Phdr *phdr;
	int i;
	char *bufp;
	long int nr_cpus = 0;
	unsigned long long notes_addr;

	bufp = (char*) buf;

	/* Setup ELF Header*/
	elf = (Elf64_Ehdr *) bufp;
	bufp += sizeof(Elf64_Ehdr);
	memcpy(elf->e_ident, ELFMAG, SELFMAG);
	elf->e_ident[EI_CLASS]  = ELFCLASS64;
	elf->e_ident[EI_DATA]   = ELFDATA2LSB;
	elf->e_ident[EI_VERSION]= EV_CURRENT;
	elf->e_ident[EI_OSABI] = ELFOSABI_NONE;
	memset(elf->e_ident+EI_PAD, 0, EI_NIDENT-EI_PAD);
	elf->e_type	= ET_CORE;
	elf->e_machine	= EM_X86_64;
	elf->e_version	= EV_CURRENT;
	elf->e_entry	= 0;
	elf->e_phoff	= sizeof(Elf64_Ehdr);
	elf->e_shoff	= 0;
	elf->e_flags	= 0;
	elf->e_ehsize   = sizeof(Elf64_Ehdr);
	elf->e_phentsize= sizeof(Elf64_Phdr);
	elf->e_phnum    = 0;
	elf->e_shentsize= 0;
	elf->e_shnum    = 0;
	elf->e_shstrndx = 0;

	/* PT_NOTE program headers. One per cpu*/
	nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
	if (nr_cpus < 0) {
		return -1;
	}

	/* Need to find a better way to determine per cpu notes section size. */
#define MAX_NOTE_BYTES	1024
	for (i = 0; i < nr_cpus; i++) {
		if (get_crash_notes_section_addr (i, &notes_addr) < 0) {
			/* This cpu is not present. Skip it. */
			continue;
		}

		phdr = (Elf64_Phdr *) bufp;
		bufp += sizeof(Elf64_Phdr);
		phdr->p_type	= PT_NOTE;
		phdr->p_flags	= 0;
		phdr->p_offset  = phdr->p_paddr = notes_addr;
		phdr->p_vaddr   = 0;
		phdr->p_filesz	= phdr->p_memsz	= MAX_NOTE_BYTES;
		/* Do we need any alignment of segments? */
		phdr->p_align	= 0;

		/* Increment number of program headers. */
		(elf->e_phnum)++;
	}

	/* Setup PT_LOAD type program header for every system RAM chunk.
	 * A seprate program header for Backup Region*/
	for (i = 0; i < CRASH_MAX_MEMORY_RANGES; i++) {
		unsigned long long mstart, mend;
		mstart = crash_memory_range[i].start;
		mend = crash_memory_range[i].end;
		if (!mstart && !mend)
			break;
		phdr = (Elf64_Phdr *) bufp;
		bufp += sizeof(Elf64_Phdr);
		phdr->p_type	= PT_LOAD;
		phdr->p_flags	= PF_R|PF_W|PF_X;
		if (mstart == BACKUP_START && mend == BACKUP_END)
			phdr->p_offset	= info->backup_start;
		else
			phdr->p_offset	= mstart;

		/* Handle linearly mapped region.*/

		/* Filling the vaddr conditionally as we have two linearly
		 * mapped regions here. One is __START_KERNEL_map 0 to 40 MB
		 * other one is PAGE_OFFSET */

		if ((mend <= (MAXMEM - 1)) && mstart < KERNEL_TEXT_SIZE)
			phdr->p_vaddr = mstart + __START_KERNEL_map;
		else {
			if (mend <= (MAXMEM - 1))
				phdr->p_vaddr = mstart + PAGE_OFFSET;
			else
				phdr->p_vaddr = -1ULL;
		}
		phdr->p_paddr = mstart;
		phdr->p_filesz	= phdr->p_memsz	= mend - mstart + 1;
		/* Do we need any alignment of segments? */
		phdr->p_align	= 0;

		/* Increment number of program headers. */
		(elf->e_phnum)++;
	}
	return 0;
}

/* Prepares the crash memory elf32 headers and stores in supplied buffer. */
static int prepare_crash_memory_elf32_headers(struct kexec_info *info,
						void *buf, unsigned long size)
{
	Elf32_Ehdr *elf;
	Elf32_Phdr *phdr;
	int i;
	char *bufp;
	long int nr_cpus = 0;
	unsigned long long notes_addr;

	bufp = (char*) buf;

	/* Setup ELF Header*/
	elf = (Elf32_Ehdr *) bufp;
	bufp += sizeof(Elf32_Ehdr);
	memcpy(elf->e_ident, ELFMAG, SELFMAG);
	elf->e_ident[EI_CLASS]  = ELFCLASS32;
	elf->e_ident[EI_DATA]   = ELFDATA2LSB;
	elf->e_ident[EI_VERSION]= EV_CURRENT;
	elf->e_ident[EI_OSABI] = ELFOSABI_NONE;
	memset(elf->e_ident+EI_PAD, 0, EI_NIDENT-EI_PAD);
	elf->e_type	= ET_CORE;
	elf->e_machine	= EM_X86_64;
	elf->e_version	= EV_CURRENT;
	elf->e_entry	= 0;
	elf->e_phoff	= sizeof(Elf32_Ehdr);
	elf->e_shoff	= 0;
	elf->e_flags	= 0;
	elf->e_ehsize   = sizeof(Elf32_Ehdr);
	elf->e_phentsize= sizeof(Elf32_Phdr);
	elf->e_phnum    = 0;
	elf->e_shentsize= 0;
	elf->e_shnum    = 0;
	elf->e_shstrndx = 0;

	/* PT_NOTE program headers. One per cpu*/
	nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
	if (nr_cpus < 0) {
		return -1;
	}

	/* Need to find a better way to determine per cpu notes section size. */
#define MAX_NOTE_BYTES	1024
	for (i = 0; i < nr_cpus; i++) {
		if (get_crash_notes_section_addr (i, &notes_addr) < 0) {
			/* This cpu is not present. Skip it. */
			return -1;
		}
		phdr = (Elf32_Phdr *) bufp;
		bufp += sizeof(Elf32_Phdr);
		phdr->p_type	= PT_NOTE;
		phdr->p_flags	= 0;
		phdr->p_offset  = phdr->p_paddr = notes_addr;
		phdr->p_vaddr   = 0;
		phdr->p_filesz	= phdr->p_memsz	= MAX_NOTE_BYTES;
		/* Do we need any alignment of segments? */
		phdr->p_align	= 0;

		/* Increment number of program headers. */
		(elf->e_phnum)++;
	}

	/* Setup PT_LOAD type program header for every system RAM chunk.
	 * A seprate program header for Backup Region*/
	for (i = 0; i < CRASH_MAX_MEMORY_RANGES; i++) {
		unsigned long long mstart, mend;
		mstart = crash_memory_range[i].start;
		mend = crash_memory_range[i].end;
		if (!mstart && !mend)
			break;
		phdr = (Elf32_Phdr *) bufp;
		bufp += sizeof(Elf32_Phdr);
		phdr->p_type	= PT_LOAD;
		phdr->p_flags	= PF_R|PF_W|PF_X;
		if (mstart == BACKUP_START && mend == BACKUP_END)
			phdr->p_offset	= info->backup_start;
		else
			phdr->p_offset	= mstart;
		/* Handle linearly mapped region.*/

		/* Filling the vaddr conditionally as we have two linearly
		 * mapped regions here. One is __START_KERNEL_map 0 to 40 MB
		 * other one is PAGE_OFFSET */

		if (mend <= (MAXMEM - 1) && mstart < KERNEL_TEXT_SIZE)
			phdr->p_vaddr = mstart + __START_KERNEL_map;
		else {
			if (mend <= (MAXMEM - 1))
				phdr->p_vaddr = mstart + PAGE_OFFSET;
			else
				phdr->p_vaddr = UINT_MAX;
		}
		phdr->p_paddr = mstart;
		phdr->p_filesz	= phdr->p_memsz	= mend - mstart + 1;
		/* Do we need any alignment of segments? */
		phdr->p_align	= 0;
		/* Increment number of program headers. */
		(elf->e_phnum)++;
	}
	return 0;
}

