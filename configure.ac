dnl Define ourselves
AC_INIT(tclpkcs11, @@VERS@@)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_GNU_SOURCE

dnl Determine system information
DC_CHK_OS_INFO

dnl Perform Tcl Extension required stuff
TCLEXT_INIT

dnl Determine how to make shared objects
if test "$TCLEXT_BUILD" != 'static'; then
	dnl Determine how to make shared objects
	DC_GET_SHOBJFLAGS

	EXTENSION_TARGET="tclpkcs11.${SHOBJEXT}"
else
	dnl Hard-code the archive extension to be .a
	AREXT='a'
	AC_CHECK_TOOL([AR], [ar], [false])
	AC_CHECK_TOOL([RANLIB], [ranlib], [:])

	EXTENSION_TARGET="tclpkcs11.${AREXT}"
fi
AC_SUBST(EXTENSION_TARGET)
AC_SUBST(TCLEXT_BUILD)

dnl Find out if we have the functions needed to open shared objects
AC_SEARCH_LIBS(dlopen, dl,, [
	AC_SEARCH_LIBS(shl_load, dld dl)
])
AC_CHECK_FUNCS(dlopen shl_load)

dnl Look for appropriate headers
AC_CHECK_HEADERS(unistd.h stdlib.h string.h strings.h dlfcn.h dl.h)

dnl Setup a stable ABI
DC_SETUP_STABLE_API([${srcdir}/tclpkcs11.vers], tclpkcs11.syms)

dnl Produce output
AC_OUTPUT(Makefile pkgIndex.tcl tclpkcs11.syms)
