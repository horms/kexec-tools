#ifndef KEXEC_MIPS_H
#define KEXEC_MIPS_H

#define MAX_MEMORY_RANGES  64
#define MAX_LINE          160

#define CORE_TYPE_ELF32 1
#define CORE_TYPE_ELF64 2
extern unsigned char setup_simple_start[];
extern uint32_t setup_simple_size;

extern struct {
	uint32_t spr8;
	uint32_t spr9;
} setup_simple_regs;

int elf_mips_probe(const char *buf, off_t len);
int elf_mips_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info);
void elf_mips_usage(void);

struct arch_options_t {
	int      core_header_type;
};

#endif /* KEXEC_MIPS_H */
