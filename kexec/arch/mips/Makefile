#
# kexec mips (linux booting linux)
#
mips_KEXEC_SRCS =  kexec/arch/mips/kexec-mips.c
mips_KEXEC_SRCS += kexec/arch/mips/kexec-elf-mips.c
mips_KEXEC_SRCS += kexec/arch/mips/kexec-elf-rel-mips.c
mips_KEXEC_SRCS += kexec/arch/mips/crashdump-mips.c

mips_ADD_BUFFER =
mips_ADD_SEGMENT =
mips_VIRT_TO_PHYS =

dist += kexec/arch/mips/Makefile $(mips_KEXEC_SRCS)			\
	kexec/arch/mips/kexec-mips.h					\
	kexec/arch/mips/crashdump-mips.h				\
	kexec/arch/mips/include/arch/options.h

CFLAGS +=-Wall -Werror
