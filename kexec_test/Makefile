#
# kexec_test Debugging payload to be certain the infrastructure works
#
RELOC:=0x10000
KEXEC_TEST_S_SRCS:= kexec_test/kexec_test16.S kexec_test/kexec_test.S
KEXEC_TEST_S_OBJS:=$(patsubst %.S, %.o, $(KEXEC_TEST_S_SRCS))
KEXEC_TEST_S_DEPS:=$(patsubst %.S, %.d, $(KEXEC_TEST_S_SRCS))
KEXEC_TEST_SRCS:= $(KEXEC_TEST_S_SRCS)
KEXEC_TEST_OBJS:= $(KEXEC_TEST_S_OBJS)
KEXEC_TEST_DEPS:= $(KEXEC_TEST_S_DEPS)
KEXEC_TEST:=$(PKGLIBDIR)/kexec_test

-include $(KEXEC_TEST_DEPS)

$(KEXEC_TEST): CPPFLAGS+=-DRELOC=$(RELOC)
$(KEXEC_TEST): ASFLAGS+=-m32
#$(KEXEC_TEST): LDFLAGS=-m32 -Wl,-e -Wl,_start -Wl,-Ttext -Wl,$(RELOC) \
#		       -nostartfiles
$(KEXEC_TEST): LDFLAGS=-melf_i386 -e _start -Ttext $(RELOC)

$(KEXEC_TEST): $(KEXEC_TEST_OBJS)
	mkdir -p $(@D)
	#$(LINK.o) -o $@ $^
	$(LD) $(LDFLAGS) -o $@ $^
