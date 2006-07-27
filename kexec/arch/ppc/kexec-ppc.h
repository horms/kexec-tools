#ifndef KEXEC_PPC_H
#define KEXEC_PPC_H

extern unsigned char setup_simple_start[];
extern uint32_t setup_simple_size;

extern struct {
	uint32_t spr8;
} setup_simple_regs;

extern unsigned char setup_dol_start[];
extern uint32_t setup_dol_size;

extern struct {
	uint32_t spr8;
} setup_dol_regs;

int elf_ppc_probe(const char *buf, off_t len);
int elf_ppc_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info);
void elf_ppc_usage(void);

int dol_ppc_probe(const char *buf, off_t len);
int dol_ppc_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info);
void dol_ppc_usage(void);

#endif /* KEXEC_PPC_H */
