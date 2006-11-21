#
# kexec (linux booting linux)
#
PURGATORY_HEX_C:= $(OBJDIR)/kexec/purgatory.c

$(PURGATORY_HEX_C): $(PURGATORY) $(BIN_TO_HEX)
	$(MKDIR) -p $(@D)
	$(BIN_TO_HEX) purgatory < $(PURGATORY) > $@

KCFLAGS:= $(CFLAGS) $(EXTRA_CFLAGS) -Ikexec/arch/$(ARCH)/include

KEXEC_C_SRCS:= kexec/kexec.c 
KEXEC_C_SRCS+= kexec/ifdown.c
KEXEC_C_SRCS+= kexec/kexec-elf.c 
KEXEC_C_SRCS+= kexec/kexec-elf-exec.c 
KEXEC_C_SRCS+= kexec/kexec-elf-core.c
KEXEC_C_SRCS+= kexec/kexec-elf-rel.c 
KEXEC_C_SRCS+= kexec/kexec-elf-boot.c 
KEXEC_C_SRCS+= kexec/kexec-iomem.c
KEXEC_C_SRCS+= kexec/crashdump.c
KEXEC_C_GENERATED_SRCS+= $(PURGATORY_HEX_C)
KEXEC_S_SRCS:= 
KEXEC_S_GENERATED_SRCS:=
include kexec/arch/$(ARCH)/Makefile

KEXEC_C_OBJS:= $(patsubst %.c, $(OBJDIR)/%.o, $(KEXEC_C_SRCS) \
	       $(KEXEC_C_GENERATED_SRCS))
KEXEC_C_DEPS:= $(patsubst %.c, $(OBJDIR)/%.d, $(KEXEC_C_SRCS))
KEXEC_C_DUMMY_DEPS:= $(patsubst %.c, $(OBJDIR)/%.d, $(KEXEC_C_GENERATED_SRCS))
KEXEC_S_OBJS:= $(patsubst %.S, $(OBJDIR)/%.o, $(KEXEC_S_SRCS) \
	       $(KEXEC_S_GENERATED_SRCS))
KEXEC_S_DEPS:= $(patsubst %.S, $(OBJDIR)/%.d, $(KEXEC_S_SRCS))
KEXEC_S_DUMMY_DEPS:= $(patsubst %.c, $(OBJDIR)/%.d, $(KEXEC_S_GENERATED_SRCS))
KEXEC_SRCS:= $(KEXEC_C_SRCS) $(KEXEC_S_SRCS)
KEXEC_OBJS:= $(KEXEC_C_OBJS) $(KEXEC_S_OBJS)
KEXEC_DEPS:= $(KEXEC_C_DEPS) $(KEXEC_S_DEPS)
KEXEC:= $(SBINDIR)/kexec
KEXEC_MANPAGE:= $(MANDIR)/man8/kexec.8

include $(KEXEC_DEPS)

$(KEXEC_C_DEPS): $(OBJDIR)/%.d: %.c
	mkdir -p $(@D)
	$(CC) $(KCFLAGS) -M $< | sed -e 's|$(patsubst %.d,%.o,$(@F))|$(patsubst %.d,%.o,$(@))|' > $@

$(KEXEC_S_DEPS): $(OBJDIR)/%.d: %.S
	mkdir -p $(@D)
	$(CC) $(KCFLAGS) -M $< | sed -e 's|$(patsubst %.d,%.o,$(@F))|$(patsubst %.d,%.o,$(@))|' > $@

# This is needed to ensure that the rule below that depend
# on each .c file having a .d file don't break
$(KEXEC_C_DUMMY_DEPS): $(OBJDIR)/%.d: %.c
	mkdir -p $(@D)
	touch $@

# This is needed to ensure that the rule below that depend
# on each .S file having a .d file don't break
$(KEXEC_S_DUMMY_DEPS): $(OBJDIR)/%.d: %.S
	mkdir -p $(@D)
	touch $@

$(KEXEC_C_OBJS): $(OBJDIR)/%.o: %.c $(OBJDIR)/%.d
	mkdir -p $(@D)
	$(CC) $(KCFLAGS) -o $@ -c $<

$(KEXEC_S_OBJS): $(OBJDIR)/%.o: %.S $(OBJDIR)/%.d
	mkdir -p $(@D)
	$(CC) $(KCFLAGS) -o $@ -c $<

$(KEXEC): $(KEXEC_OBJS) $(UTIL_LIB)
	mkdir -p $(@D)
	$(CC) $(LDFLAGS) $(EXTRA_LDFLAGS) $(KCFLAGS) -o $@ \
		$(KEXEC_OBJS) $(UTIL_LIB) $(LIBS)

$(KEXEC_MANPAGE): kexec/kexec.8
	 $(MKDIR) -p     $(MANDIR)/man8
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

