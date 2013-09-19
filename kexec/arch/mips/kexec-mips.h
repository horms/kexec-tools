#ifndef KEXEC_MIPS_H
#define KEXEC_MIPS_H

#define MAX_MEMORY_RANGES  64
#define MAX_LINE          160

#define CORE_TYPE_ELF32 1
#define CORE_TYPE_ELF64 2

int elf_mips_probe(const char *buf, off_t len);
int elf_mips_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info);
void elf_mips_usage(void);

struct arch_options_t {
	int      core_header_type;
};

#endif /* KEXEC_MIPS_H */
