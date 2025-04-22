#
# kexec riscv
#
riscv_KEXEC_SRCS = kexec/arch/riscv/crashdump-riscv.c
riscv_KEXEC_SRCS += kexec/arch/riscv/kexec-elf-riscv.c
riscv_KEXEC_SRCS += kexec/arch/riscv/kexec-riscv.c

riscv_DT_OPS += kexec/dt-ops.c

riscv_MEM_REGIONS = kexec/mem_regions.c

riscv_ARCH_REUSE_INITRD =

riscv_CPPFLAGS += -I $(srcdir)/kexec/

dist += $(riscv_KEXEC_SRCS)				\
	kexec/arch/riscv/include/arch/options.h		\
	kexec/arch/riscv/iomem.h			\
	kexec/arch/riscv/kexec-riscv.h			\
	kexec/arch/riscv/Makefile

ifdef HAVE_LIBFDT

LIBS += -lfdt

else

include $(srcdir)/kexec/libfdt/Makefile.libfdt

libfdt_SRCS += $(LIBFDT_SRCS:%=kexec/libfdt/%)

riscv_CPPFLAGS += -I$(srcdir)/kexec/libfdt

riscv_KEXEC_SRCS += $(libfdt_SRCS)

endif
