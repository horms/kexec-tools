#include <stdio.h>
#include <elf.h>
#include <string.h>
#include "../../kexec.h"
#include "../../kexec-elf.h"

int machine_verify_elf_rel(struct mem_ehdr *ehdr)
{
	if (ehdr->ei_data != ELFDATA2MSB) {
		return 0;
	}
	if (ehdr->ei_class != ELFCLASS64) {
		return 0;
	}
	if (ehdr->e_machine != EM_PPC64) {
		return 0;
	}
	return 1;
}

static struct mem_shdr *toc_section(const struct mem_ehdr *ehdr)
{
	struct mem_shdr *shdr, *shdr_end;
	unsigned char *strtab;
	strtab = (unsigned char *)ehdr->e_shdr[ehdr->e_shstrndx].sh_data;
	shdr_end = &ehdr->e_shdr[ehdr->e_shnum];
	for(shdr = ehdr->e_shdr; shdr != shdr_end; shdr++)
		if ( shdr->sh_size &&
			strcmp((char *)&strtab[shdr->sh_name],
						".toc") == 0)
			return shdr;
	return NULL;
}

/* r2 is the TOC pointer: it actually points 0x8000 into the TOC (this
   gives the value maximum span in an instruction which uses a signed
   offset) */
unsigned long my_r2(const struct mem_ehdr *ehdr)
{
	struct mem_shdr *shdr;
	shdr = toc_section(ehdr);
	if (!shdr) {
		die("TOC reloc without a toc section?");
	}
	return shdr->sh_addr + 0x8000;
}


void machine_apply_elf_rel(struct mem_ehdr *ehdr, unsigned long r_type,
	void *location, unsigned long address, unsigned long value)
{
	switch(r_type) {
	case R_PPC64_ADDR32:
		/* Simply set it */
		*(uint32_t *)location = value;
		break;

	case R_PPC64_ADDR64:
	case R_PPC64_REL64:
		/* Simply set it */
		*(uint64_t *)location = value;
		break;

	case R_PPC64_TOC:
		*(uint64_t *)location = my_r2(ehdr);
		break;

	case R_PPC64_TOC16_DS:
		/* Subtact TOC pointer */
		value -= my_r2(ehdr);
		if ((value & 3) != 0 || value + 0x8000 > 0xffff) {
			die("bad TOC16_DS relocation (%lu)\n", value);
		}
		*((uint16_t *) location)
			= (*((uint16_t *) location) & ~0xfffc)
			| (value & 0xfffc);
		break;

	case R_PPC64_REL24:
		/* Convert value to relative */
		value -= address;
		if (value + 0x2000000 > 0x3ffffff || (value & 3) != 0){
			die("REL24 %li out of range!\n",
				(long int)value);
		}

		/* Only replace bits 2 through 26 */
		*(uint32_t *)location = (*(uint32_t *)location & ~0x03fffffc)
					| (value & 0x03fffffc);
		break;

	case R_PPC64_ADDR16_LO:
		*(uint16_t *)location = value & 0xffff;
		break;

	case R_PPC64_ADDR16_HI:
		*(uint16_t *)location = (value>>16) & 0xffff;
		break;

	case R_PPC64_ADDR16_HA:
		*(uint16_t *)location = (((value+0x8000)>>16)  & 0xffff);
		break;

	case R_PPC64_ADDR16_HIGHEST:
		*(uint16_t *)location = (((uint64_t)value>>48)  & 0xffff);
		break;
	case R_PPC64_ADDR16_HIGHER:
		*(uint16_t *)location = (((uint64_t)value>>32)  & 0xffff);
		break;

	default:
		die("Unknown rela relocation: %lu\n", r_type);
		break;
	}
	return;
}
