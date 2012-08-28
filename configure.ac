AC_PREREQ(2.57)

dnl
dnl autoconf initialisation
dnl
AC_INIT([unicornscan], [0.4.7], [osace-users@lists.sourceforge.net])
AC_CONFIG_HEADERS([src/config.h:src/config.h.in])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_AUX_DIR([autostuff])
dnl AC_CONFIG_MACRO_DIR([m4])

dnl
dnl get defaults for use later in an ugly way
dnl
BUILD_DIR=`pwd`
top_builddir=`pwd`
top_srcdir=`pwd`

U_COPTS="${CFLAGS}"
U_CDEFS=""
U_CINCS="${CPPFLAGS}"
U_LDFLAGS="${LDFLAGS}"
U_LIBS=""

targetname="unicornscan"
sendername="unisend"
listenername="unilisten"

AC_MSG_RESULT(configuring unicornscan version ${PACKAGE_VERSION})

AC_LBL_C_INIT(U_COPTS, U_CINCS)

AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_C_VOLATILE

AC_SUBST(LIBTOOL_DEPS)

LIBS=""
AC_LBL_LIBRARY_NET
U_LIBS="${LIBS}"

dnl
dnl checks for programs.
dnl 
AC_PROG_AWK
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
dnl we dont really even need the end user to have this, we ship pre-generated ones now
dnl AC_PROG_LEX
dnl AC_PROG_YACC

dnl
dnl checks for typedefs, structures, and compiler features.
dnl
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_OFF_T
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T

dnl
dnl checks for header files.
dnl
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_HEADER_DIRENT
AC_HEADER_TIME
AC_CHECK_HEADERS([fcntl.h inttypes.h malloc.h memory.h netdb.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/param.h sys/time.h unistd.h limits.h])

AC_CHECK_HEADERS([sys/socket.h], [], [], [#include <sys/types.h>
])

AC_CHECK_HEADERS([net/if.h netinet/in.h], [], [], [#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
])

AC_CHECK_HEADERS([arpa/inet.h ifaddrs.h net/if_dl.h ifaddrs.h net/bpf.h net/ethernet.h sys/ethernet.h netinet/if_ether.h netinet/ether.h netpacket/packet.h], [], [], [#include <sys/types.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
])

AC_CHECK_MEMBER([struct sockaddr.sa_len], [AC_DEFINE(HAVE_STRUCT_SOCKADDR_LEN)], [], [#include <sys/types.h>
#include <sys/socket.h>])

dnl
dnl checks for library functions.
dnl
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([alarm gethostbyname gettimeofday inet_ntoa memset select socket strdup strerror strstr strrchr getnameinfo getaddrinfo])

AC_SEARCH_LIBS([nanosleep], [rt posix4])
AC_SEARCH_LIBS([inet_aton], [resolv])

dnl
dnl checks for other libraries and features
dnl

NEED_AUX_LIBS=""

AC_UNI_LIBPCAP
AC_UNI_LIBDNET
AC_UNI_LIBLTDL
dnl AC_UNI_SELINUX
AC_UNI_PROCNETROUTE

dnl XXX hack until selinux code is updated, the above macro is no longer called...
CHCON=true
SP_MODE=755
shlibs=.la
AC_SUBST(CHCON)
AC_SUBST(SP_MODE)
AC_DEFINE_UNQUOTED(SHLIB_EXT, "$shlibs")

AC_UNI_PRNG
AC_PATH_PROGS(USE_MAKE, gmake gnumake make)

AX_C___ATTRIBUTE__

dnl execinfo.h -> real test
AC_MSG_CHECKING(for backtrace in execinfo.h)
AC_LINK_IFELSE([
#include <stdio.h>
#include <execinfo.h>
int main(int argc, char ** argv) {
        void *bs[[50]]; int sz=0;
        sz=backtrace(bs, 50);
        backtrace_symbols_fd(bs, sz, 2);
        exit(0);
}
], [AC_MSG_RESULT(yes)
AC_DEFINE(WITH_BACKTRACE)], [AC_MSG_RESULT(no)])

bundled_ltdl="no"
AC_MSG_CHECKING([whether to force bundled libltdl to be staticly linked into executables])
AC_ARG_ENABLE(bundled-ltdl,
[  --enable-bundled-ltdl   staticly link against bundled ltdl, not system wide version],
[bundled_ltdl="yes"],
[bundled_ltdl="no"])
case "$bundled_ltdl" in
yes)
	AC_MSG_RESULT([yes])
	NEED_AUX_LIBS="${NEED_AUX_LIBS} libltdl"
	;;
*)
	AC_MSG_RESULT([no])
	;;
esac

AC_ARG_ENABLE(debug-support,
[  --enable-debug-support  enable possibly unsafe debugging functions],
[
AC_DEFINE(DEBUG_SUPPORT)
U_COPTS="${U_COPTS} -ggdb -Wall -pipe -Wshadow -Wcast-align -Wcast-qual -Wchar-subscripts -Wno-deprecated-declarations -Wformat-security -Wimplicit -Wsign-compare -Wuninitialized -Wunused -Wwrite-strings -Wmissing-format-attribute -Wmissing-noreturn -Wmissing-braces -Wparentheses -Wsequence-point -Wno-format-y2k"
], [])

AC_SUBST(NEED_AUX_LIBS)

dnl check for non-priv user
AC_MSG_CHECKING(for non-priv user for listener)
AC_ARG_WITH(listen-user, 
[  --with-listen-user      enable username for listener (default nobody)],
[listen_user="$withval"],
[listen_user="nobody"])

case "$listen_user" in
yes)
	listen_user="nobody"
	AC_MSG_RESULT([Using user nobody])
	AC_DEFINE_UNQUOTED(NOPRIV_USER, "$listen_user")
	;;
no)
	AC_MSG_ERROR([using a listen-user of no is silly, what i was looking for was a username])
	;;
*)
	AC_MSG_RESULT([Using user $listen_user])
	AC_DEFINE_UNQUOTED(NOPRIV_USER, "$listen_user")
	;;
esac
AC_SUBST(NOPRIV_USER)

case "${host_cpu}" in
x86_64)
	U_CFLAGS="${U_CFLAGS} -fPIC"
	;;
esac

case "${host_os}" in
*linux*)
	AC_DEFINE(USE_SETRE)
	;;
*netbsd*)
	AC_DEFINE(USE_SETRE)
	;;
*freebsd*)
	AC_DEFINE(USE_SETRE)
	;;
*darwin*)
	;;
*solaris*)
	;;
*aix*)
	;;
esac

DBTYPES=""
MY_LDFLAGS=""
MY_CPPFLAGS=""
PG_LDFLAGS=""
PG_CPPFLAGS=""
mysql="no"
pgsql="no"

dnl lifted from the snort mysql configure.in
default_directory="/usr /usr/local /usr/local/mysql"

AC_ARG_WITH(mysql,
    [  --with-mysql=DIR        support for mysql],
    [ with_mysql="$withval" ],
    [ with_mysql=no ])
if test "$with_mysql" != "no"; then
  if test "$with_mysql" = "yes"; then
    mysql_directory="$default_directory";
    mysql_fail="yes"
  elif test -d $withval; then
    mysql_directory="$withval"
    mysql_fail="no"
  elif test "$with_mysql" = ""; then
    mysql_directory="$default_directory";
    mysql_fail="no"
  fi
  AC_MSG_CHECKING(for mysql)
  for i in $mysql_directory; do
    if test -r $i/include/mysql/mysql.h; then
      MYSQL_DIR=$i
      MYSQL_INC_DIR=$i/include/mysql
    elif test -r $i/include/mysql.h; then
      MYSQL_DIR=$i
      MYSQL_INC_DIR=$i/include
    fi
  done
  if test -z "$MYSQL_DIR"; then
    if test "$mysql_fail" != "no"; then
      AC_MSG_ERROR(cant find mysql headers (mysql.h), rerun configure with --with-mysql=/path/to/mysql/prefix, 1)
    else
      AC_MSG_RESULT(no)
    fi
  else
    for i in lib lib/mysql; do
      str="$MYSQL_DIR/$i/libmysqlclient.*"
      for j in `echo $str`; do
        if test -r $j; then
          MYSQL_LIB_DIR="$MYSQL_DIR/$i"
          break 2
        fi
      done
    done
    if test -z "$MYSQL_LIB_DIR"; then
      if test "$mysql_fail" != "no"; then
        AC_MSG_ERROR(cant find mysqlclient library, libmysqlclient.?, rerun configure --with-mysql=/path/to/mysql/prefix, 1)
      else
        AC_MSG_RESULT(no)
      fi
    else
      AC_MSG_RESULT(yes)
      AC_DEFINE(WITH_MYSQL)
      AC_CHECK_LIB(z, compress)
      MY_LDFLAGS="-L${MYSQL_LIB_DIR}"
      MY_CPPFLAGS="-I${MYSQL_INC_DIR}"
      DBTYPES="${DBTYPES} mysql"
      mysql="yes"
    fi
  fi
fi

default_directory="/usr /usr/local /usr/local/pgsql /usr/local/postgresql"

AC_ARG_WITH(pgsql,
    [  --with-pgsql=DIR        support for PostgreSQL],
    [ with_pgsql="$withval" ],
    [ with_pgsql=no ])
if test "$with_pgsql" != "no"; then
  if test "$with_pgsql" = "yes"; then
    pgsql_directory="$default_directory";
    pgsql_fail="yes"
  elif test -d $withval; then
    pgsql_directory="$withval"
    pgsql_fail="no"
  elif test "$with_pgsql" = ""; then
    pgsql_directory="$default_directory";
    pgsql_fail="no"
  fi
  AC_MSG_CHECKING(for PostgreSQL)
  for i in $pgsql_directory; do
    if test -r $i/include/libpq-fe.h; then
      PGSQL_DIR=$i
      PGSQL_INC_DIR=$i/include
    fi
  done
  if test -z "$PGSQL_DIR"; then
    if test "$pgsql_fail" != "no"; then
      tmp=""
      for i in $pgsql_directory; do
        tmp="$tmp $i/include"
      done
      AC_MSG_ERROR(cant find PostgreSQL header libpq-fe.h, rerun configure with --with-pgsql=/path/to/pgsql/prefix, 1)
    else
      AC_MSG_RESULT(no)
    fi
  else
    for i in lib lib/postgresql; do
      str="$PGSQL_DIR/$i/libpq.*"
      for j in `echo $str`; do
        if test -r $j; then
          PGSQL_LIB_DIR="$PGSQL_DIR/$i"
          break 2
        fi
      done
    done
    if test -z "$PGSQL_LIB_DIR"; then
      if test "$pgsql_fail" != "no"; then
        AC_MSG_ERROR(cant find PostgreSQL pq library, rerun configure with --with-pgsql=/path/to/pgsql/prefix, 1)
      else
        AC_MSG_RESULT(no)
      fi
    else
      AC_MSG_RESULT(yes)
      AC_DEFINE(WITH_PGSQL)
      PG_LDFLAGS="${LDFLAGS} -L${PGSQL_LIB_DIR}"
      PG_CPPFLAGS="${CPPFLAGS} -I${PGSQL_INC_DIR}"
      DBTYPES="${DBTYPES} pgsql"
      pgsql="yes"
    fi
  fi
fi

AC_CHECK_LIB([GeoIP], [GeoIP_open], [], [], [])

AC_SUBST(DESTDIR)
AC_SUBST(DBTYPES)
AC_SUBST(PG_LDFLAGS)
AC_SUBST(PG_CPPFLAGS)
AC_SUBST(MY_LDFLAGS)
AC_SUBST(MY_CPPFLAGS)

dnl check for getopt_long
AC_MSG_CHECKING(for getopt_long)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>]], [[getopt_long(0,NULL,NULL,NULL,NULL);]])],[AC_MSG_RESULT(yes)
AC_DEFINE(WITH_LONGOPTS)],[AC_MSG_RESULT(no)
])

dnl check for cpu endianess
AC_C_BIGENDIAN(AC_DEFINE(CPU_BIGENDIAN), AC_DEFINE(CPU_LITTLEENDIAN), AC_MSG_ERROR(no no no you dont))

dnl checks for special files

U_CDEFS="${DEFS} ${U_CDEFS}"
U_COPTS="${CFLAGS} ${U_COPTS}"
U_CINCS="${CPPFLAGS} ${U_CINCS}"
U_LDFLAGS="${LDFLAGS} ${U_LDFLAGS}"
U_LIBS="${U_LIBS} ${UNILDADD}"

AC_SUBST(U_COPTS)
AC_SUBST(U_CDEFS)
AC_SUBST(U_CINCS)
AC_SUBST(U_LDFLAGS)
AC_SUBST(U_LIBS)

AC_SUBST(sendername, $sendername)
AC_SUBST(listenername, $listenername)
AC_SUBST(targetname, $targetname)
AC_DEFINE_UNQUOTED(SENDERNAME, "$sendername")
AC_DEFINE_UNQUOTED(TARGETNAME, "$targetname")
AC_DEFINE_UNQUOTED(LISTENERNAME, "$listenername")

AC_CONFIG_FILES([Makefile
		Makefile.inc
		etc/Makefile
		libs/Makefile
		docs/Makefile
		selinux/Makefile
		ext_src/Makefile
		src/Makefile
		src/packageinfo.h
		src/unilib/Makefile
		src/scan_progs/Makefile
		src/scan_progs/tests/Makefile
		src/tools/Makefile
		src/tools/p0f/Makefile
		src/output_modules/Makefile
		src/output_modules/database/Makefile
		src/payload_modules/Makefile
		src/payload_modules/libunirainbow/Makefile
		src/report_modules/Makefile
		src/report_modules/osdetect/Makefile
		src/parse/Makefile])

AC_OUTPUT

selinux=no
if test $CHCON = chcon; then
	selinux=yes
fi

echo
echo "--                Configuration Summary                                      --"
echo "prefix:                           ${prefix}"
echo "PostgreSQL Support:               $pgsql"
echo "MySQL Support:                    $mysql"
echo "GeoIP support:                    $ac_cv_lib_GeoIP_GeoIP_open"
echo "SELinux Support:                  $selinux"
echo "Listen User: (non-selinux)        $listen_user"
echo "libraries missing that will be built:  \`$NEED_AUX_LIBS'"
echo "C options  = $U_COPTS"
echo "C defines  = $U_CDEFS"
echo "C include  = $U_CINCS"
echo "Link Flags = $U_LDFLAGS"
echo "type $USE_MAKE to build"

echo
