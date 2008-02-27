#
# kexec mipsel (linux booting linux)
#
mipsel_KEXEC_SRCS =  kexec/arch/mipsel/kexec-mipsel.c
mipsel_KEXEC_SRCS += kexec/arch/mipsel/kexec-elf-mipsel.c
mipsel_KEXEC_SRCS += kexec/arch/mipsel/kexec-elf-rel-mipsel.c
mipsel_KEXEC_SRCS += kexec/arch/mipsel/mipsel-setup-simple.S

dist += kexec/arch/mipsel/Makefile $(mipsel_KEXEC_SRCS)			\
	kexec/arch/mipsel/kexec-mipsel.h				\
	kexec/arch/mipsel/include/arch/options.h

