#
# Purgatory ppc64
#

ppc64_PURGATORY_SRCS += purgatory/arch/ppc64/v2wrap.S
ppc64_PURGATORY_SRCS += purgatory/arch/ppc64/hvCall.S
ppc64_PURGATORY_SRCS += purgatory/arch/ppc64/purgatory-ppc64.c
ppc64_PURGATORY_SRCS += purgatory/arch/ppc64/console-ppc64.c
ppc64_PURGATORY_SRCS += purgatory/arch/ppc64/crashdump_backup.c

ppc64_PURGATORY_EXTRA_CFLAGS += -m64 -mcall-aixdesc
ppc64_PURGATORY_EXTRA_ASFLAGS += -m64 -mcall-aixdesc
ppc64_PURGATORY_EXTRA_LDFLAGS += -melf64ppc

dist += purgatory/arch/ppc64/Makefile $(ppc64_PURGATORY_SRCS)		\
	purgatory/arch/ppc64/purgatory-ppc64.h
