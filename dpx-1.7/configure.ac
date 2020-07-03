# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.69)
AC_INIT([dpx], [1.7], [snort-team@sourcefire.com])
AC_CONFIG_SRCDIR([src/dpx.c])
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Use the same defines Snort used
# (absolutely critical to ensure struct definitions match)
CFLAGS=`pkg-config --cflags snort`
CPPFLAGS=""

# not sure why this is borked
#AC_ENABLE_VISIBILITY()
#
# so we do like snort:
# modified from gnulib/m4/visibility.m4
AC_DEFUN([CC_VISIBILITY],
[
    AC_REQUIRE([AC_PROG_CC])
    AC_MSG_CHECKING([for visibility support])
    AC_CACHE_VAL(gl_cv_cc_visibility, [
        gl_save_CFLAGS="$CFLAGS"
        # Add -Werror flag since some compilers, e.g. icc 7.1, don't support it,
        # but only warn about it instead of compilation failing
        CFLAGS="$CFLAGS -Werror -fvisibility=hidden"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
            extern __attribute__((__visibility__("hidden"))) int hiddenvar;
            extern __attribute__((__visibility__("default"))) int exportedvar;
            extern __attribute__((__visibility__("hidden"))) int hiddenfunc (void);
            extern __attribute__((__visibility__("default"))) int exportedfunc (void);]],
            [[]])],
            [gl_cv_cc_visibility="yes"],
            [gl_cv_cc_visibility="no"])
    ])   
    AC_MSG_RESULT([$gl_cv_cc_visibility])
    if test "x$gl_cv_cc_visibility" = "xyes"; then 
        CFLAGS="$gl_save_CFLAGS -fvisibility=hidden"
        AC_DEFINE([HAVE_VISIBILITY],[1],
            [Define if the compiler supports visibility declarations.])
    else 
        CFLAGS="$gl_save_CFLAGS"
    fi   
])
CC_VISIBILITY()

# Checks for libraries.
AC_ARG_WITH(dpx_includes,
            [  --with-dpx-includes=DIR    libdpx include directory],
            [with_dpx_includes="$withval"], [with_dpx_includes="no"])

if test "x$with_dpx_includes" != "xno"; then
    CPPFLAGS="${CPPFLAGS} -I${with_dpx_includes}"
    SOURCE="${with_dpx_includes}"
fi

# Checks for header files.
AC_CHECK_HEADERS([ \
    inttypes.h \
    memory.h \
    netdb.h \
    netinet/in.h \
    stdint.h \
    stdlib.h \
    string.h \
    sys/ioctl.h \
    sys/param.h \
    sys/socket.h \
    sys/time.h \
    unistd.h \
])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_SIZEOF([char])
AC_CHECK_SIZEOF([short])
AC_CHECK_SIZEOF([int])
AC_CHECK_SIZEOF([long int])
AC_CHECK_SIZEOF([long long int])
AC_CHECK_SIZEOF([unsigned int])
AC_CHECK_SIZEOF([unsigned long int])
AC_CHECK_SIZEOF([unsigned long long int])

# Check for int types
AC_CHECK_TYPES([u_int8_t,u_int16_t,u_int32_t,u_int64_t])
AC_CHECK_TYPES([uint8_t,uint16_t,uint32_t,uint64_t])
AC_CHECK_TYPES([int8_t,int16_t,int32_t,int64_t])

AC_CHECK_TYPES([boolean])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([ \
    gethostbyname \
    getpagesize \
    memset \
    munmap \
    socket \
    strchr \
    strcspn \
    strdup \
    strerror \
    strrchr \
    strstr \
    strtoul \
])

AC_CONFIG_FILES([ \
    Makefile \
    src/Makefile \
    test/Makefile \
])

AC_SUBST(SOURCE)

AC_OUTPUT

