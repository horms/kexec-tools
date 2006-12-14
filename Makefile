# Hey Emacs this is a -*- makefile-*-
include Makefile.conf
VERSION=1.102
DATE=28 July 2006
PACKAGE=kexec-tools

pkgdatadir = $(datadir)/$(PACKAGE)
pkglibdir = $(libdir)/$(PACKAGE)
pkgincludedir = $(includedir)/$(PACKAGE)

# You can specify DESTDIR on the command line to do a add
# a prefix to the install so it doesn't really happen
# Useful for building binary packages
DESTDIR =

EXTRA_CPPFLAGS:= -I./include -I./util_lib/include \
	-DVERSION='"$(VERSION)"' -DRELEASE_DATE='"$(DATE)"' \
	-DPACKAGE='"$(PACKAGE)"' $(DEFS) $(EXTRA_CFLAGS)

PREFIX:=$(OBJDIR)/build
SBINDIR=$(PREFIX)/sbin
BINDIR=$(PREFIX)/bin
LIBEXECDIR=$(PREFIX)/libexec
DATADIR=$(PREFIX)/share
SYSCONFDIR=$(PREFIX)/etc
SHAREDSTATEDIR=$(PREFIX)/com
LOCALSTATEDIR=$(PREFIX)/var
LIBDIR=$(PREFIX)/lib
INFODIR=$(PREFIX)/info
MANDIR=$(PREFIX)/man
MAN1DIR=$(MANDIR)/man1
MAN2DIR=$(MANDIR)/man2
MAN3DIR=$(MANDIR)/man3
MAN4DIR=$(MANDIR)/man4
MAN5DIR=$(MANDIR)/man5
MAN6DIR=$(MANDIR)/man6
MAN7DIR=$(MANDIR)/man7
MAN8DIR=$(MANDIR)/man8
INCLUDEDIR=$(PREFIX)/include

PKGDATADIR=$(DATADIR)/$(PACKAGE)
PKGLIBDIR=$(LIBDIR)/$(PACKAGE)
PKGINCLUDEIR=$(INCLUDEDIR)/$(PACKAGE)

MAN_PAGES:= kexec/kexec.8
MAN_PAGES+= kdump/kdump.8
BINARIES_i386:=  $(SBINDIR)/kexec $(PKGLIBDIR)/kexec_test
BINARIES_x86_64:=$(SBINDIR)/kexec $(PKGLIBDIR)/kexec_test
BINARIES:=$(SBINDIR)/kexec $(SBINDIR)/kdump $(BINARIES_$(ARCH)) 

TARGETS:=$(BINARIES) $(MAN_PAGES)

all: $(TARGETS)

# cc-option
# Usage: cflags-y += $(call cc-option, -march=winchip-c6, -march=i586)
cc-option = $(shell if $(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(1) -S -o /dev/null \
	     -xc /dev/null > /dev/null 2>&1; then echo "$(1)"; else \
	     echo "$(2)"; fi ;)

# Utility function library
#
include util_lib/Makefile

#
# Stand alone utilities
#
include util/Makefile

#
# purgatory (code between kernels)
#
include purgatory/Makefile

#
# kexec (linux booting linux)
#
include kexec/Makefile


# kdump (read a crashdump from memory)
#
include kdump/Makefile

#
# kexec_test (test program)
#
ifeq ($(ARCH),i386)
include kexec_test/Makefile
endif
ifeq ($(ARCH),x86_64)
include kexec_test/Makefile
endif

SPEC=$(PACKAGE).spec
GENERATED_SRCS:= ./configure ./$(SPEC)
TARBALL=$(OBJDIR)/$(PACKAGE)-$(VERSION).tar.gz
SRCS:=$(shell $(FIND) \
	./AUTHORS ./COPYING ./News ./TODO \
	./Makefile ./Makefile.conf.in ./configure.ac \
	./kexec-tools.spec.in ./config ./doc \
	./include ./kexec ./purgatory ./kexec_test ./kdump ./util ./util_lib \
	! -path '*CVS*' ! -name '*~' ! -name '.*' \
	-type f -print )
SRCS+=$(GENERATED_SRCS)
PSRCS:=$(patsubst ./%,$(PACKAGE)-$(VERSION)/%,$(SRCS))

Makefile.conf: Makefile.conf.in configure
	/bin/sh ./configure

configure: configure.ac
	autoconf
	$(RM) -rf autom4te.cache

tarball: $(TARBALL)

$(TARBALL): $(SRCS) $(SPEC)
	$(MKDIR) -p $(OBJDIR)
	$(RM) -f $(OBJDIR)/$(PACKAGE)-$(VERSION)
	$(LN) -s .. $(OBJDIR)/$(PACKAGE)-$(VERSION)
	(cd $(OBJDIR); $(TAR) -cf - $(PSRCS) | gzip -9) > $@

rpm: $(TARBALL)
	$(MKDIR) -p $(OBJDIR)/RPM $(OBJDIR)/SRPM $(OBJDIR)/BUILD $(OBJDIR)/SPECS \
		$(OBJDIR)/TMP $(OBJDIR)/SOURCES
	unset MAKEFLAGS MAKELEVEL; \
	$(RPMBUILD) -ta \
		--define '_rpmdir $(OBJDIR)/RPM' \
		--define '_srcrpmdir $(OBJDIR)/SRPM' \
		--define '_builddir $(OBJDIR)/BUILD' \
		--define '_specdir $(OBJDIR)/SPECS' \
		--define '_tmppath $(OBJDIR)/TMP' \
		--define '_sourcedir $(OBJDIR)/SOURCES' \
		$(TARBALL)

$(SPEC): kexec-tools.spec.in Makefile
	$(SED) -e 's,^Version: $$,Version: $(VERSION),' $< > $@

echo::
	@echo ARCH=$(ARCH)
	@echo BINARIES=$(BINARIES)
	@echo TARGETS=$(TARGETS)
	@echo CC=$(CC)
	@echo AR=$(AR)
	@echo LD=$(LD)

clean:
	@$(FIND) $(OBJDIR) ! -name '*.d' -type f | $(XARGS) $(RM) rm -f
	@$(RM) -rf rpm
	@$(RM) -f config.log config.status config.cache
	@$(RM) -f $(TARBALL)

dist-clean: clean
	@$(RM) -rf $(OBJDIR)
	@$(FIND) . -type f -name '*~' -o -name '*.orig' | $(XARGS) $(RM) -f
	@$(RM) -f Makefile.conf

maintainer-clean: dist-clean
	@$(RM) -f $(GENERATED_SRCS)


install: $(TARGETS)
	for file in $(TARGETS) ; do \
		if test `$(DIRNAME) $$file` =     "$(SBINDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(sbindir)/; \
			$(INSTALL) -m 555  $$file $(DESTDIR)/$(sbindir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(BINDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(bindir)/; \
			$(INSTALL) -m 555 $$file $(DESTDIR)/$(bindir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(LIBEXECDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(libexecdir)/; \
			$(INSTALL) -m 555 $$file $(DESTDIR)/$(libexecdir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(DATADIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(datadir)/; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(datadir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(SYSCONFDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(sysconfdir)/; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(sysconfdir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(SHAREDSTATEDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(sharedstatedir)/; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(sharedstatedir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(LOCALSTATEDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(localstatedir)/; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(localstatedir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(LIBDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(libdir)/; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(libdir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(INFODIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(infodir)/; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(infodir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(MAN1DIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(mandir)/man1; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(mandir)/man1; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(MAN2DIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(mandir)/man2; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(mandir)/man2; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(MAN3DIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(mandir)/man3/; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(mandir)/man3/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(MAN4DIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(mandir)/man4/; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(mandir)/man4/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(MAN5DIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(mandir)/man5/; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(mandir)/man5/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(MAN6DIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(mandir)/man6/; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(mandir)/man6/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(MAN7DIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(mandir)/man7/; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(mandir)/man7/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(MAN8DIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(mandir)/man8/; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(mandir)/man8/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(INCLUDEDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(includedir)/; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(includedir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(PKGDATADIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(pkgdatadir)/; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(pkgdatadir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(PKGLIBDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(pkglibdir)/; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(pkglibdir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(PKGINCLUDEDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(pkgincludedir)/; \
			$(INSTALL) -m 444 $$file $(DESTDIR)/$(pkgincludedir)/; \
		fi; \
	done

.PHONY: echo install all clean dist-clean maintainer-clean tarball rpm
