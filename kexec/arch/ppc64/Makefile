#
# kexec ppc64 (linux booting linux)
#
ppc64_KEXEC_SRCS =  kexec/arch/ppc64/kexec-elf-rel-ppc64.c
ppc64_KEXEC_SRCS += kexec/arch/ppc64/kexec-zImage-ppc64.c
ppc64_KEXEC_SRCS += kexec/arch/ppc64/kexec-elf-ppc64.c
ppc64_KEXEC_SRCS += kexec/arch/ppc64/kexec-ppc64.c
ppc64_KEXEC_SRCS += kexec/arch/ppc64/crashdump-ppc64.c

ppc64_ARCH_REUSE_INITRD =

ppc64_FS2DT	    = kexec/fs2dt.c
ppc64_FS2DT_INCLUDE = -include $(srcdir)/kexec/arch/ppc64/crashdump-ppc64.h \
                      -include $(srcdir)/kexec/arch/ppc64/kexec-ppc64.h

dist += kexec/arch/ppc64/Makefile $(ppc64_KEXEC_SRCS)			\
	kexec/arch/ppc64/kexec-ppc64.h kexec/arch/ppc64/crashdump-ppc64.h \
	kexec/arch/ppc64/include/arch/options.h

