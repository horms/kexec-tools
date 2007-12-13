#
# kexec (linux booting linux)
#
PURGATORY_HEX_C:= kexec/purgatory.c

$(PURGATORY_HEX_C): $(PURGATORY) $(BIN_TO_HEX)
	$(MKDIR) -p $(@D)
	$(BIN_TO_HEX) purgatory < $(PURGATORY) > $@

KEXEC_C_SRCS:= kexec/kexec.c
KEXEC_C_SRCS+= kexec/ifdown.c
KEXEC_C_SRCS+= kexec/kexec-elf.c
KEXEC_C_SRCS+= kexec/kexec-elf-exec.c
KEXEC_C_SRCS+= kexec/kexec-elf-core.c
KEXEC_C_SRCS+= kexec/kexec-elf-rel.c
KEXEC_C_SRCS+= kexec/kexec-elf-boot.c
KEXEC_C_SRCS+= kexec/kexec-iomem.c
KEXEC_C_SRCS+= kexec/crashdump.c
KEXEC_C_SRCS+= kexec/crashdump-xen.c
KEXEC_C_GENERATED_SRCS+= $(PURGATORY_HEX_C)
KEXEC_S_SRCS:=
KEXEC_S_GENERATED_SRCS:=

include $(srcdir)/kexec/arch/$(ARCH)/Makefile

KEXEC_C_OBJS:= $(patsubst %.c, %.o, $(KEXEC_C_SRCS) $(KEXEC_C_GENERATED_SRCS))
KEXEC_C_DEPS:= $(patsubst %.c, %.d, $(KEXEC_C_SRCS))
KEXEC_S_OBJS:= $(patsubst %.S, %.o, $(KEXEC_S_SRCS) $(KEXEC_S_GENERATED_SRCS))
KEXEC_S_DEPS:= $(patsubst %.S, %.d, $(KEXEC_S_SRCS))
KEXEC_SRCS:= $(KEXEC_C_SRCS) $(KEXEC_S_SRCS)
KEXEC_OBJS:= $(KEXEC_C_OBJS) $(KEXEC_S_OBJS)
KEXEC_DEPS:= $(KEXEC_C_DEPS) $(KEXEC_S_DEPS)
KEXEC:= $(SBINDIR)/kexec
KEXEC_MANPAGE:= $(MANDIR)/man8/kexec.8

-include $(KEXEC_DEPS)

$(KEXEC): $(KEXEC_OBJS) $(UTIL_LIB)
	@$(MKDIR) -p $(@D)
	$(LINK.o) -o $@ $^

$(KEXEC): CPPFLAGS+=-I$(srcdir)/kexec/arch/$(ARCH)/include

$(KEXEC_MANPAGE): kexec/kexec.8
	@$(MKDIR) -p     $(MANDIR)/man8
	cp kexec/kexec.8 $(KEXEC_MANPAGE)
echo::
	@echo "KEXEC_C_SRCS $(KEXEC_C_SRCS)"
	@echo "KEXEC_C_DEPS $(KEXEC_C_DEPS)"
	@echo "KEXEC_C_OBJS $(KEXEC_C_OBJS)"
	@echo "KEXEC_S_SRCS $(KEXEC_S_SRCS)"
	@echo "KEXEC_S_DEPS $(KEXEC_S_DEPS)"
	@echo "KEXEC_S_OBJS $(KEXEC_S_OBJS)"
	@echo "KEXEC_SRCS $(KEXEC_SRCS)"
	@echo "KEXEC_DEPS $(KEXEC_DEPS)"
	@echo "KEXEC_OBJS $(KEXEC_OBJS)"

