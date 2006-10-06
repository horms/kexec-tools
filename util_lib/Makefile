#
# Utility function library
#
UTIL_LIB_SRCS:=util_lib/compute_ip_checksum.c
UTIL_LIB_SRCS+=util_lib/sha256.c
UTIL_LIB_OBJS:=$(patsubst %.c, $(OBJDIR)/%.o, $(UTIL_LIB_SRCS))
UTIL_LIB_DEPS:=$(patsubst %.c, $(OBJDIR)/%.d, $(UTIL_LIB_SRCS))
UTIL_LIB:=$(OBJDIR)/libutil.a

include $(UTIL_LIB_DEPS)

$(UTIL_LIB_DEPS): $(OBJDIR)/%.d: %.c 
	$(MKDIR) -p $(@D)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -M $< | sed -e 's|$(patsubst %.d,%.o,$(@F))|$(patsubst %.d,%.o,$(@))|' > $@

# sha256.c needs to be compiled without optimization, else
# purgatory fails to execute (on ia64 at least).
# By placing -O0 after $(CFLAGS), which is provided by
# the prevailing environment, it overrides any other -O flags
# provided.
$(UTIL_LIB_OBJS): $(OBJDIR)/%.o: %.c $(OBJDIR)/%.d
	$(MKDIR) -p $(@D)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -O0 -c -o $@ $<

$(UTIL_LIB): $(UTIL_LIB_OBJS)
	$(MKDIR) -p $(@D)
	$(AR) rs $(UTIL_LIB) $(UTIL_LIB_OBJS)

