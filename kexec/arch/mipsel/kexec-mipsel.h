#ifndef KEXEC_MIPS_H
#define KEXEC_MIPS_H

extern unsigned char setup_simple_start[];
extern uint32_t setup_simple_size;

extern struct {
	uint32_t spr8;
	uint32_t spr9;
} setup_simple_regs;

int elf_mipsel_probe(const char *buf, off_t len);
int elf_mipsel_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info);
void elf_mipsel_usage(void);

#endif /* KEXEC_MIPS_H */
