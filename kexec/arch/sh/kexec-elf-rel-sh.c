#include <stdio.h>
#include <elf.h>
#include "../../kexec.h"
#include "../../kexec-elf.h"

int machine_verify_elf_rel(struct mem_ehdr *ehdr)
{

        die("machine_verify_elf_rel is not implemented\n");
	return 0;
}

void machine_apply_elf_rel(struct mem_ehdr *ehdr, unsigned long r_type,
	void *location, unsigned long address, unsigned long value)
{
        die("Unknown rela relocation: %lu\n", r_type);
	return;
}
