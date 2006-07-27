#include <stdio.h>
#include <elf.h>
#include "../../kexec.h"
#include "../../kexec-elf.h"

int machine_verify_elf_rel(struct mem_ehdr *ehdr)
{
	if (ehdr->ei_data != ELFDATA2LSB) {
		return 0;
	}
	if (ehdr->ei_class != ELFCLASS64) {
		return 0;
	}
	if (ehdr->e_machine != EM_IA_64) {
		return 0;
	}
	return 1;
}

void machine_apply_elf_rel(struct mem_ehdr *ehdr, unsigned long r_type,
	void *location, unsigned long address, unsigned long value)
{
	switch(r_type) {
	case R_IA64_NONE:
		break;
	case R_IA64_DIR64LSB:
		*((uint64_t *)location) = value;
		break;
	case R_IA64_DIR32LSB:
		*((uint32_t *)location) = value;
		if (value != *((uint32_t *)location))
			goto overflow;
		break;
	case R_IA64_PCREL21B:
	case R_IA64_LTOFF22:
	case R_IA64_SEGREL64LSB:
	default:
		die("Unknown rela relocation: %lu\n", r_type);
		break;
	}
	return;
 overflow:
	die("overflow in relocation type %lu val %Lx\n", 
		r_type, value);
}
