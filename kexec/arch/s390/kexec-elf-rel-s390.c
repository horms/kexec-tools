/*
 * kexec/arch/s390/kexec-elf-rel-s390.c
 *
 * (C) Copyright IBM Corp. 2005
 *
 * Author(s): Heiko Carstens <heiko.carstens@de.ibm.com>
 *
 */

#include <stdio.h>
#include <elf.h>
#include "../../kexec.h"
#include "../../kexec-elf.h"

int machine_verify_elf_rel(struct mem_ehdr *ehdr)
{
	return 0;
}

void machine_apply_elf_rel(struct mem_ehdr *ehdr, unsigned long r_type,
	void *location, unsigned long address, unsigned long value)
{
}
