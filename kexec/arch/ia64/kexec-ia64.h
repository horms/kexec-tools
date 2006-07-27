#ifndef KEXEC_IA64_H
#define KEXEC_IA64_H

int elf_ia64_probe(const char *buf, off_t len);
int elf_ia64_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info);
void elf_ia64_usage(void);

#endif /* KEXEC_IA64_H */
