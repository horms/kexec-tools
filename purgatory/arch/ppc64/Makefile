#
# Purgatory ppc
#

PURGATORY_S_SRCS += purgatory/arch/ppc64/v2wrap.S
PURGATORY_C_SRCS += purgatory/arch/ppc64/purgatory-ppc64.c
PURGATORY_C_SRCS += purgatory/arch/ppc64/console-ppc64.c
PURGATORY_C_SRCS += purgatory/arch/ppc64/crashdump_backup.c

$(PURGATORY): CFLAGS += -m64 -mcall-aixdesc
$(PURGATORY): ASFLAGS += -m64 -mcall-aixdesc
$(PURGATORY): LDFLAGS += -melf64ppc
