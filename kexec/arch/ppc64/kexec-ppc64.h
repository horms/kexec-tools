#ifndef KEXEC_PPC64_H
#define KEXEC_PPC64_H

int elf_ppc64_probe(const char *buf, off_t len);
int elf_ppc64_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info);
void elf_ppc64_usage(void);

#endif /* KEXEC_PPC_H */
