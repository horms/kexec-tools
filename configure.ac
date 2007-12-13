dnl 
dnl configure.ac for mkelfImage
dnl 
dnl 

dnl ---Required
AC_INIT(kexec-tools-testing, 20071030-git)
AC_CONFIG_AUX_DIR(./config)
AC_CONFIG_HEADERS([include/config.h])

AC_DEFINE_UNQUOTED(PACKAGE_DATE, "30th October 2007",
		[Define to the release date of this package])


dnl -- Compilation platform configuration
dnl -- the host specifices the host machine for the kexec binary, the
dnl -- the target specifies the architecture of the kernel to be kexeced.
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

dnl Compute ARCH from target cpu info
case $target_cpu in
	i?86 )
		ARCH="i386"
		;;
	powerpc )
		ARCH="ppc"
		;;
	powerpc64 )
		ARCH="ppc64"
		;;
	s390x|s390 )
		ARCH="s390"
		;;
	sh4|sh4a|sh3|sh )
		ARCH="sh"
		;;
	ia64|x86_64|alpha )
		ARCH="$target_cpu"
		;;
	* )
		AC_MSG_ERROR([unsupported architecture $target_cpu])
		;;
esac

dnl ---Options

OBJDIR=`pwd`/objdir
if test "${host_alias}" ; then
	OBJDIR="$OBJDIR-${host_alias}"
fi

BUILD_CFLAGS='-O2 -Wall'
TARGET_CFLAGS='-O2 -Wall'

AC_ARG_WITH([objdir], AC_HELP_STRING([--with-objdir=<dir>],[select directory for object files]),
	[ OBJDIR="$withval" ], [ OBJDIR="$OBJDIR" ])

AC_ARG_WITH([gamecube],
		AC_HELP_STRING([--with-gamecube],[enable gamecube support]),
		AC_DEFINE(WITH_GAMECUBE, 1,
			[Define to include gamecube support]))

AC_ARG_WITH([zlib], AC_HELP_STRING([--without-zlib],[disable zlib support]),
	[ with_zlib="$withval"], [ with_zlib=yes ] )

AC_ARG_WITH([xen], AC_HELP_STRING([--without-xen],
	[disable extended xen support]), [ with_xen="$withval"], [ with_xen=yes ] )

dnl ---Programs
dnl To specify a different compiler, just 'export CC=/path/to/compiler'

AC_PROG_CC

if test "${build}" != "${host}" ; then
	AC_CHECK_PROGS(BUILD_CC, [${build_alias}-gcc ${build}-gcc gcc])
else
	BUILD_CC="$CC"
fi

dnl Find compiler for target
if test "${target}" != "${host}" ; then
	AC_CHECK_PROGS(TARGET_CC, [${target_alias}-gcc ${target}-gcc gcc])
else
	TARGET_CC="$CC"
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
	AC_CHECK_HEADER(zlib.h,
		AC_CHECK_LIB(z, inflateInit_, ,
		AC_MSG_NOTICE([zlib support disabled])))
fi

dnl find Xen control stack libraries
if test "$with_xen" = yes ; then
	AC_CHECK_HEADER(xenctrl.h,
		AC_CHECK_LIB(xenctrl, xc_version, ,
		AC_MSG_NOTICE([Xen support disabled])))
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
AC_SUBST([TARGET_CC])
AC_SUBST([TARGET_CFLAGS])
AC_SUBST([ASFLAGS])

AC_SUBST([ARCH])
AC_SUBST([OBJDIR])
AC_SUBST([INSTALL])

dnl ---Output
AC_OUTPUT([Makefile])
