#ifndef KEXEC_ELF_H
#define KEXEC_ELF_H

struct kexec_info;

struct mem_ehdr {
	unsigned ei_class;
	unsigned ei_data;
	unsigned e_type;
	unsigned e_machine;
	unsigned e_version;
	unsigned e_flags;
	unsigned e_phnum;
	unsigned e_shnum;
	unsigned e_shstrndx;
	unsigned long e_entry;
	unsigned long e_phoff;
	unsigned long e_shoff;
	unsigned e_notenum;
	struct mem_phdr *e_phdr;
	struct mem_shdr *e_shdr;
	struct mem_note *e_note;
	unsigned long rel_addr, rel_size;
};

struct mem_phdr {
	unsigned long p_paddr;
	unsigned long p_vaddr;
	unsigned long p_filesz;
	unsigned long p_memsz;
	unsigned long p_offset;
	const char *p_data;
	unsigned p_type;
	unsigned p_flags;
	unsigned p_align;
};

struct mem_shdr {
	unsigned sh_name;
	unsigned sh_type;
	unsigned long sh_flags;
	unsigned long sh_addr;
	unsigned long sh_offset;
	unsigned long sh_size;
	unsigned sh_link;
	unsigned sh_info;
	unsigned long sh_addralign;
	unsigned long sh_entsize;
	const unsigned char *sh_data;
};

struct mem_sym {
	unsigned long st_name;   /* Symbol name (string tbl index) */
	unsigned char st_info;   /* No defined meaning, 0 */
	unsigned char st_other;  /* Symbol type and binding */
	unsigned long st_shndx;  /* Section index */
	unsigned long st_value;  /* Symbol value */
	unsigned long st_size;   /* Symbol size */
};

struct  mem_rela {
	unsigned long r_offset;
	unsigned long r_sym;
	unsigned long r_type;
	unsigned long r_addend;
};

struct mem_note {
	unsigned n_type;
	unsigned n_descsz;
	const char *n_name;
	const void *n_desc;
};

/* The definition of an ELF note does not vary depending
 * on ELFCLASS.
 */
typedef struct
{
	uint32_t n_namesz;		/* Length of the note's name.  */
	uint32_t n_descsz;		/* Length of the note's descriptor.  */
	uint32_t n_type;		/* Type of the note.  */
} ElfNN_Nhdr;

/* Misc flags */

#define ELF_SKIP_FILESZ_CHECK		0x00000001

extern void free_elf_info(struct mem_ehdr *ehdr);
extern int build_elf_info(const char *buf, off_t len, struct mem_ehdr *ehdr,
				uint32_t flags);
extern int build_elf_exec_info(const char *buf, off_t len,
				struct mem_ehdr *ehdr, uint32_t flags);
extern int build_elf_rel_info(const char *buf, off_t len, struct mem_ehdr *ehdr,
				uint32_t flags);

extern int build_elf_core_info(const char *buf, off_t len,
					struct mem_ehdr *ehdr, uint32_t flags);
extern int elf_exec_load(struct mem_ehdr *ehdr, struct kexec_info *info);
extern int elf_rel_load(struct mem_ehdr *ehdr, struct kexec_info *info,
	unsigned long min, unsigned long max, int end);

extern void elf_exec_build_load(struct kexec_info *info, struct mem_ehdr *ehdr, 
				const char *buf, off_t len, uint32_t flags);
extern void elf_rel_build_load(struct kexec_info *info, struct mem_ehdr *ehdr, 
	const char *buf, off_t len, unsigned long min, unsigned long max, 
	int end, uint32_t flags);

extern int elf_rel_find_symbol(struct mem_ehdr *ehdr,
	const char *name, struct mem_sym *ret_sym);
extern unsigned long elf_rel_get_addr(struct mem_ehdr *ehdr, const char *name);
extern void elf_rel_set_symbol(struct mem_ehdr *ehdr,
	const char *name, const void *buf, size_t size);
extern void elf_rel_get_symbol(struct mem_ehdr *ehdr,
	const char *name, void *buf, size_t size);

uint16_t elf16_to_cpu(const struct mem_ehdr *ehdr, uint16_t value);
uint32_t elf32_to_cpu(const struct mem_ehdr *ehdr, uint32_t value);
uint64_t elf64_to_cpu(const struct mem_ehdr *ehdr, uint64_t value);

uint16_t cpu_to_elf16(const struct mem_ehdr *ehdr, uint16_t value);
uint32_t cpu_to_elf32(const struct mem_ehdr *ehdr, uint32_t value);
uint64_t cpu_to_elf64(const struct mem_ehdr *ehdr, uint64_t value);

unsigned long elf_max_addr(const struct mem_ehdr *ehdr);

/* Architecture specific helper functions */
extern int machine_verify_elf_rel(struct mem_ehdr *ehdr);
extern void machine_apply_elf_rel(struct mem_ehdr *ehdr, unsigned long r_type, 
	void *location, unsigned long address, unsigned long value);
#endif /* KEXEC_ELF_H */

