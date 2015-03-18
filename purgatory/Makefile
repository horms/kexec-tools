#
# Purgatory (an uncomfortable intermediate state)
#            In this case the code that runs between kernels
#

# There is probably a cleaner way to do this but for now this
# should keep us from accidentially include unsafe library functions
# or headers.

PURGATORY = purgatory/purgatory.ro
PURGATORY_SRCS =
PURGATORY_SRCS += purgatory/purgatory.c
PURGATORY_SRCS += purgatory/printf.c
PURGATORY_SRCS += purgatory/string.c

dist += purgatory/Makefile $(PURGATORY_SRCS)				\
	purgatory/include/purgatory.h purgatory/include/string.h

include $(srcdir)/purgatory/arch/alpha/Makefile
include $(srcdir)/purgatory/arch/arm/Makefile
include $(srcdir)/purgatory/arch/i386/Makefile
include $(srcdir)/purgatory/arch/ia64/Makefile
include $(srcdir)/purgatory/arch/mips/Makefile
include $(srcdir)/purgatory/arch/ppc/Makefile
include $(srcdir)/purgatory/arch/ppc64/Makefile
include $(srcdir)/purgatory/arch/s390/Makefile
include $(srcdir)/purgatory/arch/sh/Makefile
include $(srcdir)/purgatory/arch/x86_64/Makefile

PURGATORY_SRCS+=$($(ARCH)_PURGATORY_SRCS)

PURGATORY_OBJS = $(call objify, $(PURGATORY_SRCS)) purgatory/sha256.o
PURGATORY_DEPS = $(call depify, $(PURGATORY_OBJS))

clean += $(PURGATORY_OBJS) $(PURGATORY_DEPS) $(PURGATORY)

-include $(PURGATORY_DEPS)

# sha256.c needs to be compiled without optimization, else
# purgatory fails to execute on ia64.
purgatory/sha256.o: CFLAGS += -O0

purgatory/sha256.o: $(srcdir)/util_lib/sha256.c
	mkdir -p $(@D)
	$(COMPILE.c) -o $@ $^

$(PURGATORY): CC=$(TARGET_CC)
$(PURGATORY): CFLAGS+=$(PURGATORY_EXTRA_CFLAGS) \
		      $($(ARCH)_PURGATORY_EXTRA_CFLAGS) \
		      -Os -fno-builtin -ffreestanding \
		      -fno-zero-initialized-in-bss

$(PURGATORY): CPPFLAGS=$($(ARCH)_PURGATORY_EXTRA_CFLAGS) \
			-I$(srcdir)/purgatory/include \
			-I$(srcdir)/purgatory/arch/$(ARCH)/include \
			-I$(srcdir)/util_lib/include \
			-I$(srcdir)/include \
			-Iinclude \
			-I$(shell $(CC) -print-file-name=include)
$(PURGATORY): LDFLAGS=$($(ARCH)_PURGATORY_EXTRA_CFLAGS)\
			-Wl,--no-undefined -nostartfiles -nostdlib \
			-nodefaultlibs -e purgatory_start -r

$(PURGATORY): $(PURGATORY_OBJS)
	$(MKDIR) -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@.sym $^
#	$(LD) $(LDFLAGS) $(EXTRA_LDFLAGS) --no-undefined -e purgatory_start -r -o $@ $(PURGATORY_OBJS) $(UTIL_LIB)
	$(STRIP) --strip-debug -o $@ $@.sym

echo::
	@echo "PURGATORY_SRCS $(PURGATORY_SRCS)"
	@echo "PURGATORY_DEPS $(PURGATORY_DEPS)"
	@echo "PURGATORY_OBJS $(PURGATORY_OBJS)"
