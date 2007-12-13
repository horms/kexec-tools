#
# kdump (reading a crashdump from memory)
#

KDUMP_C_SRCS:= kdump/kdump.c

KDUMP_C_OBJS:= $(patsubst %.c, %.o, $(KDUMP_C_SRCS))
KDUMP_C_DEPS:= $(patsubst %.c, %.d, $(KDUMP_C_SRCS))
KDUMP_SRCS:= $(KDUMP_C_SRCS)
KDUMP_OBJS:= $(KDUMP_C_OBJS)
KDUMP_DEPS:= $(KDUMP_C_DEPS)
KDUMP:= $(SBINDIR)/kdump
KDUMP_MANPAGE:= $(MANDIR)/man8/kdump.8

-include $(KDUMP_DEPS)

$(KDUMP): $(KDUMP_OBJS)
	@$(MKDIR) -p $(@D)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $(KDUMP_OBJS)

$(KDUMP_MANPAGE): kdump/kdump.8
	$(MKDIR) -p     $(MANDIR)/man8
	cp kdump/kdump.8 $(KDUMP_MANPAGE)
echo::
	@echo "KDUMP_C_SRCS $(KDUMP_C_SRCS)"
	@echo "KDUMP_C_DEPS $(KDUMP_C_DEPS)"
	@echo "KDUMP_C_OBJS $(KDUMP_C_OBJS)"
	@echo "KDUMP_SRCS $(KDUMP_SRCS)"
	@echo "KDUMP_DEPS $(KDUMP_DEPS)"
	@echo "KDUMP_OBJS $(KDUMP_OBJS)"

