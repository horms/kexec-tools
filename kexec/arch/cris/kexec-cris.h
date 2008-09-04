#ifndef KEXEC_CRIS_H
#define KEXEC_CRIS_H

extern unsigned char setup_simple_start[];
extern uint32_t setup_simple_size;

extern struct {
	uint32_t spr8;
	uint32_t spr9;
} setup_simple_regs;

int elf_cris_probe(const char *buf, off_t len);
int elf_cris_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info);
void elf_cris_usage(void);

#endif /* KEXEC_CRIS_H */
