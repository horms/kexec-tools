#
# Utility function library
#
UTIL_LIB_SRCS +=
UTIL_LIB_SRCS += util_lib/compute_ip_checksum.c
UTIL_LIB_SRCS += util_lib/sha256.c
UTIL_LIB_OBJS =$(call objify, $(UTIL_LIB_SRCS))
UTIL_LIB_DEPS =$(call depify, $(UTIL_LIB_OBJS))
UTIL_LIB = libutil.a

-include $(UTIL_LIB_DEPS)

$(UTIL_LIB): CPPFLAGS += -I$(srcdir)/util_lib/include

$(UTIL_LIB): $(UTIL_LIB_OBJS)
	@$(MKDIR) -p $(@D)
	$(AR) rs $(UTIL_LIB) $(UTIL_LIB_OBJS)

