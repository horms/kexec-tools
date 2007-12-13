#
# Purgatory (an uncomfortable intermediate state)
#            In this case the code that runs between kernels
#

# There is probably a cleaner way to do this but for now this
# should keep us from accidentially include unsafe library functions
# or headers.

PURGATORY_C_SRCS:=
PURGATORY_C_SRCS += purgatory/purgatory.c
PURGATORY_C_SRCS += purgatory/printf.c
PURGATORY_C_SRCS += purgatory/string.c
PURGATORY_S_OBJS:=
PURGATORY:= purgatory/purgatory.ro

include $(srcdir)/purgatory/arch/$(ARCH)/Makefile

PURGATORY_C_OBJS:= $(patsubst %.c, %.o, $(PURGATORY_C_SRCS))
PURGATORY_C_DEPS:= $(patsubst %.c, %.d, $(PURGATORY_C_SRCS))
PURGATORY_S_OBJS:= $(patsubst %.S, %.o, $(PURGATORY_S_SRCS))
PURGATORY_S_DEPS:= $(patsubst %.S, %.d, $(PURGATORY_S_SRCS))
PURGATORY_SRCS:= $(PURGATORY_S_SRCS) $(PURGATORY_C_SRCS)
PURGATORY_OBJS:= $(PURGATORY_S_OBJS) $(PURGATORY_C_OBJS) purgatory/sha256.o
PURGATORY_DEPS:= $(PURGATORY_S_DEPS) $(PURGATORY_C_DEPS)

-include $(PURGATORY_DEPS)

# sha256.c needs to be compiled without optimization, else
# purgatory fails to execute on ia64.
purgatory/sha256.o: CFLAGS += -O0

purgatory/sha256.o: $(srcdir)/util_lib/sha256.c
	mkdir -p $(@D)
	$(COMPILE.c) -o $@ $^

$(PURGATORY): CC=$(TARGET_CC)
$(PURGATORY): CFLAGS+=-Os -fno-builtin -ffreestanding \
		      -fno-zero-initialized-in-bss

$(PURGATORY): CPPFLAGS+=-I$(srcdir)/purgatory/include \
			-I$(srcdir)/purgatory/arch/$(ARCH)/include \
			-I$(shell $(CC) -print-file-name=include)
$(PURGATORY): LDFLAGS+=--no-undefined -nostartfiles -nostdlib -nodefaultlibs \
			-e purgatory_start -r

$(PURGATORY): $(PURGATORY_OBJS)
	$(MKDIR) -p $(@D)
	$(LD) $(LDFLAGS) -o $@ $^

#	$(LD) $(LDFLAGS) $(EXTRA_LDFLAGS) --no-undefined -e purgatory_start -r -o $@ $(PURGATORY_OBJS) $(UTIL_LIB)

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
