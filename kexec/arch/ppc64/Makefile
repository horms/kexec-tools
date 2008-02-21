#
# kexec ppc64 (linux booting linux)
#
ppc64_KEXEC_SRCS =  kexec/arch/ppc64/kexec-elf-rel-ppc64.c
ppc64_KEXEC_SRCS += kexec/arch/ppc64/kexec-zImage-ppc64.c
ppc64_KEXEC_SRCS += kexec/arch/ppc64/fs2dt.c
ppc64_KEXEC_SRCS += kexec/arch/ppc64/kexec-elf-ppc64.c
ppc64_KEXEC_SRCS += kexec/arch/ppc64/kexec-ppc64.c
ppc64_KEXEC_SRCS += kexec/arch/ppc64/crashdump-ppc64.c

dist += kexec/arch/ppc64/Makefile $(ppc64_KEXEC_SRCS)			\
	kexec/arch/ppc64/kexec-ppc64.h kexec/arch/ppc64/crashdump-ppc64.h \
	kexec/arch/ppc64/include/arch/options.h

