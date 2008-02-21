#
# kexec sh (linux booting linux)
#
sh_KEXEC_SRCS += kexec/arch/sh/kexec-sh.c
sh_KEXEC_SRCS += kexec/arch/sh/kexec-zImage-sh.c
sh_KEXEC_SRCS += kexec/arch/sh/kexec-netbsd-sh.c
sh_KEXEC_SRCS += kexec/arch/sh/kexec-elf-rel-sh.c
sh_KEXEC_SRCS += kexec/arch/sh/netbsd_booter.S

dist += kexec/arch/sh/Makefile $(sh_KEXEC_SRCS)				\
	kexec/arch/sh/kexec-sh.h					\
	kexec/arch/sh/include/arch/options.h
