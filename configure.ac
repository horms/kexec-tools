dnl 
dnl configure.ac for mkelfImage
dnl 
dnl 

dnl ---Required
AC_INIT(Makefile.conf.in)
AC_CONFIG_AUX_DIR(./config)

dnl -- Compilation platform configuration
AC_CANONICAL_HOST
dnl Currentl AC_CANONICAL_HOST is sufficient for my needs
dnl as there are only a small number of targets that kexec
dnl can support on a given host system.  If it stops making
dnl sense compile support for all possible targets a given
dnl host can support AC_CANONICAL_TARGET may help
dnl AC_CANONICAL_TARGET


dnl Compute host cpu
case $host_cpu in 
	i?86 )	
		host_cpu="i386"
		;;
	powerpc )
		host_cpu="ppc"
		;;
	powerpc64 )
		host_cpu="ppc64"
		;;
	s390x )
		host_cpu="s390"
		;;
	sh4|sh4a|sh3 )
		host_cpu="sh"
		;;
	* ) 
		host_cpu="$host_cpu"
		;;
esac
case $host_cpu in
	i386|ppc|x86_64|alpha|ppc64|ia64|s390|sh)
		;;
	* )
		AC_MSG_ERROR([ unsupported architecture $host_cpu])
		;;
esac
ARCH=$host_cpu

dnl ---Options

OBJDIR=`pwd`/objdir
if test "${host_alias}" ; then
	OBJDIR="$OBJDIR-${host_alias}"
fi 

EXTRA_CFLAGS='-Wall -g -fno-strict-aliasing $(CPPFLAGS) $(EXTRA_CPPFLAGS)'
BUILD_CFLAGS='-O2 -Wall $(CPPFLAGS)'

# Check whether ppc64. Add -m64 for building 64-bit binary
# Add -mcall-aixdesc to generate dot-symbols as in gcc 3.3.3
if test "$ARCH" = ppc64; then
  EXTRA_CFLAGS="$EXTRA_CFLAGS -m64 -mcall-aixdesc"
fi;

AC_ARG_WITH([objdir], AC_HELP_STRING([--with-objdir=<dir>],[select directory for object files]),
	[ OBJDIR="$withval" ], [ OBJDIR="$OBJDIR" ])

AC_ARG_WITH([gamecube], AC_HELP_STRING([--with-gamecube],[enable gamecube support]),
	[ EXTRA_CFLAGS="$EXTRA_CFLAGS -DCONFIG_GAMECUBE=1" ])

AC_ARG_WITH([zlib], AC_HELP_STRING([--without-zlib],[disable gamecube support]),
	[ with_zlib="$withval"], [ with_zlib=yes ] )

AC_ARG_WITH([xen], AC_HELP_STRING([--without-xen],
	[disable extended xen support]), [ with_xen="$withval"], [ with_xen=yes ] )

dnl ---Programs
dnl To specify a different compiler, just 'export CC=/path/to/compiler'

AC_PROG_CC

if test "${build}" != "${host}" ; then
	BUILD_CC=${CC_FOR_BUILD-gcc}
else
	BUILD_CC="\$(CC)"
fi


dnl Find the compiler tool chain
AC_PROG_CPP
AC_CHECK_TOOL([LD], ld, "no", $PATH)
AC_CHECK_TOOL([AS], as, "no", $PATH)
AC_CHECK_TOOL([OBJCOPY], objcopy, "no", $PATH)
AC_CHECK_TOOL([AR], ar, "", $PATH)

dnl Find the helper functions
AC_PROG_INSTALL
AC_CHECK_PROG([MKDIR],    mkdir,    mkdir,    "no", [$PATH])
AC_CHECK_PROG([RM],       rm,       rm,       "no", [$PATH])
AC_CHECK_PROG([CP],       cp,       cp,       "no", [$PATH])
AC_CHECK_PROG([LN],       ln,       ln,       "no", [$PATH])
AC_CHECK_PROG([TAR],      tar,      tar,      "no", [$PATH])
AC_CHECK_PROG([RPMBUILD], rpmbuild, rpmbuild, "no", [$PATH])
AC_CHECK_PROG([SED],      sed,      sed,      "no", [$PATH])
AC_CHECK_PROG([FIND],     find,     find,     "no", [$PATH])
AC_CHECK_PROG([XARGS],    xargs,    xargs,    "no", [$PATH])
AC_CHECK_PROG([DIRNAME],  dirname,  dirname,  "no", [$PATH])

dnl See if I have a usable copy of zlib available
if test "$with_zlib" = yes ; then
	AC_CHECK_HEADER(zlib.h, AC_CHECK_LIB(z, inflateInit_, [AC_DEFINE(HAVE_ZLIB_H, 1) LIBS="$LIBS -lz"]))
fi

dnl find Xen control stack libraries
if test "$with_xen" = yes ; then
	AC_CHECK_HEADER(xenctrl.h, AC_CHECK_LIB(xenctrl, xc_version,
		[AC_DEFINE(HAVE_XENCTRL_H, 1) LIBS="$LIBS -lxenctrl"]))
fi

dnl ---Sanity checks
if test "$CC"      = "no"; then AC_MSG_ERROR([cc not found]) fi
if test "$CPP"     = "no"; then AC_MSG_ERROR([cpp not found]) fi
if test "$LD"      = "no"; then AC_MSG_ERROR([ld not found]) fi
if test "$AS"      = "no"; then AC_MSG_ERROR([as not found]) fi
if test "$OBJCOPY" = "no"; then	AC_MSG_ERROR([objcopy not found]) fi
if test "$AR"      = "no"; then	AC_MSG_ERROR([ar not found]) fi

if test "$MKDIR"   = "no"; then AC_MSG_ERROR([ mkdir not found]) fi 
if test "$RM"      = "no"; then AC_MSG_ERROR([ rm not found]) fi    
if test "$CP"      = "no"; then AC_MSG_ERROR([ cp not found]) fi    
if test "$LN"      = "no"; then AC_MSG_ERROR([ ln not found]) fi    
if test "$TAR"     = "no"; then AC_MSG_ERROR([ tar not found]) fi   
if test "$RPM"     = "no"; then AC_MSG_ERROR([ rpm not found]) fi   
if test "$SED"     = "no"; then AC_MSG_ERROR([ sed not found]) fi   
if test "$FIND"    = "no"; then AC_MSG_ERROR([ find not found]) fi  
if test "$XARGS"   = "no"; then AC_MSG_ERROR([ xargs not found]) fi 
if test "$DIRNAME" = "no"; then AC_MSG_ERROR([ dirname not found]) fi 

dnl ---Output variables...

AC_SUBST([BUILD_CC])
AC_SUBST([BUILD_CFLAGS])

AC_SUBST([EXTRA_CFLAGS])
AC_SUBST([ARCH])
AC_SUBST([OBJDIR])
AC_SUBST([INSTALL])

dnl ---Output
AC_OUTPUT([Makefile.conf])
