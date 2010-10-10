dnl Define ourselves
AC_INIT(tclpkcs11, 1.0)

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
DC_GET_SHOBJFLAGS

dnl Find out if we have the functions needed to open shared objects
AC_SEARCH_LIBS(dlopen, dl,, [
	AC_SEARCH_LIBS(shl_load, dld dl)
])
AC_CHECK_FUNCS(dlopen shl_load)

dnl Look for appropriate headers
AC_CHECK_HEADERS(unistd.h stdlib.h string.h strings.h dlfcn.h dl.h)

dnl Produce output
AC_OUTPUT(Makefile)