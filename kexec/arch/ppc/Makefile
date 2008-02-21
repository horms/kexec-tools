#
# kexec ppc (linux booting linux)
#
ppc_KEXEC_SRCS =  kexec/arch/ppc/kexec-ppc.c
ppc_KEXEC_SRCS += kexec/arch/ppc/kexec-elf-ppc.c
ppc_KEXEC_SRCS += kexec/arch/ppc/kexec-elf-rel-ppc.c
ppc_KEXEC_SRCS += kexec/arch/ppc/kexec-dol-ppc.c
ppc_KEXEC_SRCS += kexec/arch/ppc/ppc-setup-simple.S
ppc_KEXEC_SRCS += kexec/arch/ppc/ppc-setup-dol.S

dist += kexec/arch/ppc/Makefile $(ppc_KEXEC_SRCS)			\
	kexec/arch/ppc/kexec-ppc.h kexec/arch/ppc/ppc_asm.h		\
	kexec/arch/ppc/include/arch/options.h

