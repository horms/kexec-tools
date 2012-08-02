#
# kexec ppc (linux booting linux)
#
include $(srcdir)/kexec/arch/ppc/libfdt/Makefile.libfdt

ppc_KEXEC_SRCS =  kexec/arch/ppc/kexec-ppc.c
ppc_KEXEC_SRCS += kexec/arch/ppc/kexec-elf-ppc.c
ppc_KEXEC_SRCS += kexec/arch/ppc/kexec-elf-rel-ppc.c
ppc_KEXEC_SRCS += kexec/arch/ppc/kexec-dol-ppc.c
ppc_KEXEC_SRCS += kexec/arch/ppc/kexec-uImage-ppc.c
ppc_KEXEC_SRCS += kexec/arch/ppc/ppc-setup-simple.S
ppc_KEXEC_SRCS += kexec/arch/ppc/ppc-setup-dol.S
ppc_KEXEC_SRCS += kexec/arch/ppc/fixup_dtb.c
ppc_KEXEC_SRCS += kexec/arch/ppc/fs2dt.c
ppc_KEXEC_SRCS += kexec/arch/ppc/crashdump-powerpc.c

ppc_UIMAGE = kexec/kexec-uImage.c

libfdt_SRCS = kexec/arch/ppc/libfdt-wrapper.c
libfdt_SRCS += $(LIBFDT_SRCS:%=kexec/arch/ppc/libfdt/%)
ppc_ARCH_REUSE_INITRD =

CPPFLAGS+=-I$(srcdir)/kexec/arch/$(ARCH)/libfdt

ppc_KEXEC_SRCS += $(libfdt_SRCS)

dist += kexec/arch/ppc/Makefile $(ppc_KEXEC_SRCS)			\
	kexec/arch/ppc/crashdump-powerpc.h kexec/arch/ppc/fixup_dtb.h	\
	kexec/arch/ppc/kexec-ppc.h kexec/arch/ppc/ops.h			\
	kexec/arch/ppc/ppc_asm.h					\
	kexec/arch/ppc/include/page.h kexec/arch/ppc/include/types.h	\
	kexec/arch/ppc/include/arch/options.h
