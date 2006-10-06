#
# Purgatory (an uncomfortable intermediate state)
#            In this case the code that runs between kernels
#

# There is probably a cleaner way to do this but for now this
# should keep us from accidentially include unsafe library functions
# or headers.

ifeq ($(ARCH),ppc64)
EXTRA_LDFLAGS = -melf64ppc
endif

PCFLAGS:=-Wall -Os  \
	-I$(shell $(CC) -print-file-name=include) \
	-Ipurgatory/include -Ipurgatory/arch/$(ARCH)/include \
	$(CPPFLAGS) $(EXTRA_CPPFLAGS)

PCFLAGS += $(call cc-option, -ffreestanding)
PCFLAGS += $(call cc-option, -fnobuiltin)
PCFLAGS += $(call cc-option, -fnostdinc)
PCFLAGS += $(call cc-option, -fno-zero-initialized-in-bss)

PURGATORY_C_SRCS:=
PURGATORY_C_SRCS += purgatory/purgatory.c
PURGATORY_C_SRCS += purgatory/printf.c
PURGATORY_C_SRCS += purgatory/string.c
PURGATORY_S_OBJS:=

include purgatory/arch/$(ARCH)/Makefile


PURGATORY_C_OBJS:= $(patsubst %.c, $(OBJDIR)/%.o, $(PURGATORY_C_SRCS))
PURGATORY_C_DEPS:= $(patsubst %.c, $(OBJDIR)/%.d, $(PURGATORY_C_SRCS))
PURGATORY_S_OBJS:= $(patsubst %.S, $(OBJDIR)/%.o, $(PURGATORY_S_SRCS))
PURGATORY_S_DEPS:= $(patsubst %.S, $(OBJDIR)/%.d, $(PURGATORY_S_SRCS))
PURGATORY_SRCS:= $(PURGATORY_S_SRCS) $(PURGATORY_C_SRCS)
PURGATORY_OBJS:= $(PURGATORY_S_OBJS) $(PURGATORY_C_OBJS)
PURGATORY_DEPS:= $(PURGATORY_S_DEPS) $(PURGATORY_C_DEPS)
PURGATORY:= $(OBJDIR)/purgatory/purgatory.ro

include $(PURGATORY_DEPS)

$(PURGATORY_C_DEPS): $(OBJDIR)/%.d: %.c
	$(MKDIR) -p $(@D)
	$(CC) $(PCFLAGS) -M $< | sed -e 's|$(patsubst %.d,%.o,$(@F))|$(patsubst %.d,%.o,$(@))|' > $@

$(PURGATORY_S_DEPS): $(OBJDIR)/%.d: %.S
	$(MKDIR) -p $(@D)
	$(CC) $(PCFLAGS) -M $< | sed -e 's|$(patsubst %.d,%.o,$(@F))|$(patsubst %.d,%.o,$(@))|' > $@

$(PURGATORY_C_OBJS): $(OBJDIR)/%.o: %.c $(OBJDIR)/%.d
	$(MKDIR) -p $(@D)
	$(CC) $(PCFLAGS) -o $@ -c $<

$(PURGATORY_S_OBJS): $(OBJDIR)/%.o: %.S $(OBJDIR)/%.d
	$(MKDIR) -p $(@D)
	$(CC) $(PCFLAGS) -o $@ -c $<

$(PURGATORY): $(PURGATORY_OBJS) $(UTIL_LIB)
	$(MKDIR) -p $(@D)
	$(LD) $(LDFLAGS) $(EXTRA_LDFLAGS) --no-undefined -e purgatory_start -r -o $@ $(PURGATORY_OBJS) $(UTIL_LIB)

echo::
	@echo "PURGATORY_C_SRCS $(PURGATORY_C_SRCS)"
	@echo "PURGATORY_C_DEPS $(PURGATORY_C_DEPS)"
	@echo "PURGATORY_C_OBJS $(PURGATORY_C_OBJS)"
	@echo "PURGATORY_S_SRCS $(PURGATORY_S_SRCS)"
	@echo "PURGATORY_S_DEPS $(PURGATORY_S_DEPS)"
	@echo "PURGATORY_S_OBJS $(PURGATORY_S_OBJS)"
	@echo "PURGATORY_SRCS   $(PURGATORY_SRCS)"
	@echo "PURGATORY_DEPS   $(PURGATORY_DEPS)"
	@echo "PURGATORY_OBJS   $(PURGATORY_OBJS)"
