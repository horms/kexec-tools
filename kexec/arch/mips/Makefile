#
# kexec mips (linux booting linux)
#
mips_KEXEC_SRCS =  kexec/arch/mips/kexec-mips.c
mips_KEXEC_SRCS += kexec/arch/mips/kexec-elf-mips.c
mips_KEXEC_SRCS += kexec/arch/mips/kexec-elf-rel-mips.c
mips_KEXEC_SRCS += kexec/arch/mips/mips-setup-simple.S

dist += kexec/arch/mips/Makefile $(mips_KEXEC_SRCS)			\
	kexec/arch/mips/kexec-mips.h					\
	kexec/arch/mips/include/arch/options.h

