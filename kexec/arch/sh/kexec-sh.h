#ifndef KEXEC_SH_H
#define KEXEC_SH_H

int zImage_sh_probe(const char *buf, off_t len);
int zImage_sh_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info);
void zImage_sh_usage(void);

int netbsd_sh_probe(const char *buf, off_t len);
int netbsd_sh_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info);
void netbsd_sh_usage(void);

char *get_append(void);
unsigned long get_empty_zero(char *s);

#endif /* KEXEC_SH_H */
