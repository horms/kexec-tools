#ifndef KEXEC_ARM_H
#define KEXEC_ARM_H

int zImage_arm_probe(const char *buf, off_t len);
int zImage_arm_load(int argc, char **argv, const char *buf, off_t len,
		        struct kexec_info *info);
void zImage_arm_usage(void);

int uImage_arm_probe(const char *buf, off_t len);
int uImage_arm_load(int argc, char **argv, const char *buf, off_t len,
		        struct kexec_info *info);

#endif /* KEXEC_ARM_H */
