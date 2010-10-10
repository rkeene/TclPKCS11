dnl Define ourselves
AC_INIT(tclpkcs11, 1.0)

dnl Perform TEA related operations
TEA_INIT(3.9)
TEA_SETUP_COMPILER_CC

dnl Checks for programs.
AC_PROG_MAKE_SET
AC_AIX
AC_GNU_SOURCE

dnl Continue TEA related configuration
TEA_PATH_TCLCONFIG
TEA_LOAD_TCLCONFIG
TEA_CONFIG_CFLAGS

dnl Fix TEA's failings
dnl The TEA developers should not be let near systems
AC_SUBST(SHLIB_SUFFIX)
AC_SUBST(CC_SEARCH_FLAGS)

dnl Find out if we have the functions needed to open shared objects
AC_SEARCH_LIBS(dlopen, dl,, [
	AC_SEARCH_LIBS(shl_load, dld dl)
])
AC_CHECK_FUNCS(dlopen shl_load)

dnl Look for appropriate headers
AC_CHECK_HEADERS(unistd.h stdlib.h string.h strings.h dlfcn.h dl.h)

dnl Produce output
AC_OUTPUT(Makefile)
