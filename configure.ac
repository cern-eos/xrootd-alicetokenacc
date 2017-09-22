AC_PREREQ(2.57)
AC_INIT(xrootd-alicetokenacc, 1.3.1,[andreas.joachim.peters@cern.ch])
AC_CONFIG_SRCDIR([XrdAliceTokenAcc.cc])

AC_CANONICAL_TARGET

case "$target_os" in
   tiger*)
     AC_DEFINE(__macos__)
     ;;
   darwin*)
     AC_DEFINE(__macos__)
     ;;
   apple*)
     AC_DEFINE(__macos__)
     ;;
   linux*)
     # TODO: check why two different macros are used for this
     AC_DEFINE(__linux__)
     AC_DEFINE(__linux)
     ;;
   solaris*)
     AC_DEFINE(solaris)
     CC_PREFERENCE="cc gcc"
     CXX_PREFERENCE="CC g++"
     DFLT_OPT="-O2"
     ;;
   *)
     AC_MSG_WARN([untested operating system])
   ;;
esac

AM_INIT_AUTOMAKE(1.6 foreign)

# Test the compiler using our preferences
AC_PROG_CXX([$CXX_PREFERENCE])


echo $libdir | grep lib64 >& /dev/null
if test "$?" = "0" ; then 
   MARK64=64;
else
   MARK64="";
fi

AC_SUBST(MARK64)

AC_ARG_WITH(xrootd-location,
          [  --with-xrootd-location=installation of xrootd version to use],
          [XROOTD_LOCATION=$withval],
          [XROOTD_LOCATION=/usr/])

AC_SUBST(XROOTD_LOCATION)


AC_ARG_WITH(openssl-incdir,
          [  --with-openssl-incdir=installation of openssl header files],
          [OPENSSL_INCDIR=$withval],
          [OPENSSL_INCDIR=/usr/include/])

AC_SUBST(OPENSSL_INCDIR)

AC_ARG_WITH(openssl-libdir,
          [  --with-openssl-libdir=installation of ssl library],
          [OPENSSL_LIBDIR=$withval],
          [OPENSSL_LIBDIR=/usr/lib64/])

AC_SUBST(OPENSSL_LIBDIR)

AC_ARG_WITH(tkauthz-incdir,
          [  --with-tkauthz-incdir=installation of TTokenAuthz.h file],
          [TKAUTHZ_INCDIR=$withval],
          [TKAUTHZ_INCDIR=/usr/include])

AC_SUBST(TKAUTHZ_INCDIR)

AC_ARG_WITH(tkauthz-libdir,
          [  --with-tkauthz-libdir=installation of libTokenAuthz.so library],
          [TKAUTHZ_LIBDIR=$withval],
          [TKAUTHZ_LIBDIR=/usr/lib64/])

AC_SUBST(TKAUTHZ_LIBDIR)


AC_DEFINE(_LARGEFILE_SOURCE)
AC_DEFINE(_FILE_OFFSET_BITS,64)
AC_SYS_LARGEFILE

# Do all testing using C++
AC_LANG([C++])

# Checks for programs.
AC_PROG_CXX

dnl Disable libtool 1.5 support for languages we don't use
define([AC_LIBTOOL_LANG_F77_CONFIG], [:])dnl
define([AC_LIBTOOL_LANG_GCJ_CONFIG], [:])dnl
AC_PROG_LIBTOOL


# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([sys/time.h])

# Check for xrootd headers
if ! test -e "${XROOTD_LOCATION}/include/xrootd/XrdOuc/XrdOucString.hh"
then
   AC_MSG_ERROR([xrootd header files could not be found in directory ${XROOTD_LOCATION}])
fi

# Check for Tkauthz headers
if ! test -e "${OPENSSL_INCDIR}/openssl/sha.h"
then
   AC_MSG_ERROR([openssl header file could not be found in directory ${OPENSSL_INCDIR}])
fi 

# Check for Tkauthz lib
if ! test -e "${OPENSSL_LIBDIR}/libcrypto.so"
then
   AC_MSG_ERROR([libcrypto.so could not be found in directory ${OPENSSL_LIBDIR}])
fi 

# Check for Tkauthz headers
if ! test -e "${TKAUTHZ_INCDIR}/TTokenAuthz.h"
then
   AC_MSG_ERROR([TTokenAuthz.h header file could not be found in directory ${TKAUTHZ_INCDIR}])
fi 

# Check for Tkauthz lib
if ! test -e "${TKAUTHZ_LIBDIR}/libTokenAuthz.so"
then
   AC_MSG_ERROR([libTokenAuthz.so could not be found in directory ${TKAUTHZ_LIBDIR}])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_STAT
AC_CHECK_FUNCS([gettimeofday mkdir strdup])

AC_CONFIG_FILES([Makefile])
ln -s . XrdAliceTokenAcc

echo "=================================================="
echo "Configuring for .../lib$MARK64 library directories"
echo "=================================================="
AC_OUTPUT
