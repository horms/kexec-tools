#ifndef X86_LINUX_SETUP_H
#define X86_LINUX_SETUP_H

void init_linux_parameters(struct x86_linux_param_header *real_mode);
void setup_linux_bootloader_parameters(
	struct kexec_info *info, struct x86_linux_param_header *real_mode,
	unsigned long real_mode_base, unsigned long cmdline_offset,
	const char *cmdline, off_t cmdline_len,
	const unsigned char *initrd_buf, off_t initrd_size);
void setup_linux_system_parameters(struct x86_linux_param_header *real_mode,
					unsigned long kexec_flags);


#define SETUP_BASE    0x90000
#define KERN32_BASE  0x100000 /* 1MB */
#define INITRD_BASE 0x1000000 /* 16MB */

/* command line parameter may be appended by purgatory */
#define PURGATORY_CMDLINE_SIZE 64

#endif /* X86_LINUX_SETUP_H */
