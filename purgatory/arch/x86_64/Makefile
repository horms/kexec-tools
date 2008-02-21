#
# Purgatory x86_64
#

x86_64_PURGATORY_SRCS += purgatory/arch/x86_64/entry64-32.S
x86_64_PURGATORY_SRCS += purgatory/arch/x86_64/entry64.S
x86_64_PURGATORY_SRCS += purgatory/arch/x86_64/setup-x86_64.S
x86_64_PURGATORY_SRCS += purgatory/arch/x86_64/stack.S
x86_64_PURGATORY_SRCS += purgatory/arch/x86_64/purgatory-x86_64.c

dist += purgatory/arch/x86_64/Makefile $(x86_64_PURGATORY_SRCS) \
	purgatory/arch/x86_64/include/arch/io.h			\
	purgatory/arch/x86_64/include/arch/debug.h		\
	purgatory/arch/x86_64/purgatory-x86_64.h

# Done add sources in i386/ to dist, as i386/Makefile adds them
x86_64_PURGATORY_SRCS =  purgatory/arch/i386/entry32-16.S
x86_64_PURGATORY_SRCS += purgatory/arch/i386/entry32-16-debug.S
x86_64_PURGATORY_SRCS += purgatory/arch/i386/crashdump_backup.c
x86_64_PURGATORY_SRCS += purgatory/arch/i386/console-x86.c
x86_64_PURGATORY_SRCS += purgatory/arch/i386/vga.c
x86_64_PURGATORY_SRCS += purgatory/arch/i386/pic.c
