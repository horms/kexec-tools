#
# kdump (reading a crashdump from memory)
#

KDUMP_SRCS:= kdump/kdump.c

KDUMP_OBJS = $(call objify, $(KDUMP_SRCS))
KDUMP_DEPS = $(call depify, $(KDUMP_OBJS))

KDUMP = $(SBINDIR)/kdump
KDUMP_MANPAGE = $(MANDIR)/man8/kdump.8

dist += kdump/Makefile $(KDUMP_SRCS) kdump/kdump.8
clean += $(KDUMP_OBJS) $(KDUMP_DEPS) $(KDUMP) $(KDUMP_MANPAGE)

-include $(KDUMP_DEPS)

$(KDUMP): CC=$(TARGET_CC)
$(KDUMP): $(KDUMP_OBJS)
	@$(MKDIR) -p $(@D)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $(KDUMP_OBJS)

$(KDUMP_MANPAGE): kdump/kdump.8
	$(MKDIR) -p     $(MANDIR)/man8
	cp $^ $(KDUMP_MANPAGE)
echo::
	@echo "KDUMP_SRCS $(KDUMP_SRCS)"
	@echo "KDUMP_DEPS $(KDUMP_DEPS)"
	@echo "KDUMP_OBJS $(KDUMP_OBJS)"

