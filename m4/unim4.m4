dnl --> insert something meaningfull here <--

AC_DEFUN(AC_UNI_SELINUX, [
shlibs=".la"

AC_MSG_CHECKING(for selinux)
default_selinux_directories="/usr /usr/local /usr/local/selinux"
AC_ARG_WITH(selinux,
[  --with-selinux=PREFIX   find selinux headers and libs in this PREFIX],
[lookin="$withval"],
[lookin="$default_selinux_directories"])

if test "$lookin" = "yes"; then
	lookin="$default_selinux_directories"
fi

good=no
for g in $lookin; do
	if test -r "$g/include/selinux/selinux.h"; then
		SELINUXINC=$g
		AC_MSG_RESULT(yes, found inside $g)
		good=yes
		break
	fi
done
if test $good = "yes"; then
	dnl now check its accually enabled, due to the large number of systems with it only installed
	dnl obviously this doesnt work for cross compile XXX
	AC_MSG_CHECKING(checking that selinux is enforcing)
	enforce=0
	if test -r /selinux/enforce; then
		enforce=`cat /selinux/enforce`
	fi
	if test $enforce = 1; then
		CHCON=chcon
		SP_MODE=4511
		UNILDADD="${UNILDADD} -lselinux"
		shlibs=".so"
		AC_DEFINE(WITH_SELINUX)
		AC_MSG_RESULT(yes, sender and listener will be setuid root)
	else
		CHCON=true
		SP_MODE=755
		AC_MSG_RESULT(no, selinux is not enforcing, ignoring it)
	fi
else
	CHCON=true
	SP_MODE=755
	AC_MSG_RESULT(no)
fi

AC_SUBST(CHCON)
AC_SUBST(SP_MODE)
AC_DEFINE_UNQUOTED(SHLIB_EXT, "$shlibs")
])

AC_DEFUN(AC_UNI_PRNG, [
AC_MSG_CHECKING(for a readable prng device)
default_prng_paths="/dev/urandom /etc/random /dev/egd-pool"
AC_ARG_WITH(prng,
[  --with-prng=PATH        Use random number generator specificed by PATH],
[lookat="$withval"],
[lookat="$default_prng_paths"])

if test "$lookat" = "yes"; then
        lookat="$default_prng_paths"
fi

good=no
for g in $lookat; do
	if test -c "$g"
	then
		AC_DEFINE_UNQUOTED(RANDOM_DEVICE, "$g")
		AC_MSG_RESULT(yes found at $g)
		good=yes
		break
	elif test -S "$g"
	then
		AC_DEFINE_UNQUOTED(RANDOM_DEVICE, "$g")
		AC_MSG_RESULT(yes found at $g)
		good=yes
		break
	fi
done

if test $good = "no"; then
	AC_MSG_WARN(cant find a working random number generator, will try and make due)
	AC_DEFINE(RANDOM_DEVICE, "")
fi
AC_SUBST(RANDOM_DEVICE)
])

AC_DEFUN(AC_UNI_LIBDNET, [
AC_MSG_CHECKING(for libdnet)
default_libdnet_directories="/usr /usr/local"
lookin=$default_libdnet_directories
AC_ARG_WITH(libdnet,
[  --with-libdnet=PREFIX   use already installed libdnet in PREFIX
],
[
case "$dnet_pfx" in
no)
	lookin=""
	;;
yes)
	lookin=$default_libdnet_directories
	;;
*)
	lookin=$dnet_pfx
	;;
esac
])
good=no
if test "$lookin"; then
 	for g in $lookin; do
		if test -x "$g/bin/dnet-config"; then
			DNETLIBS=`$g/bin/dnet-config --libs`
			DNETCFLG=`$g/bin/dnet-config --cflags`
			AC_MSG_RESULT(yes, found inside $g)
			good=yes
			break
		fi
	done
fi
if test $good = "no"; then
	NEED_AUX_LIBS="${NEED_AUX_LIBS} libdnet"
	DNETLIBS=""
	DNETCFLG=""
	AC_MSG_RESULT(no, using supplied version)
fi
AC_SUBST(DNETCFLG)
AC_SUBST(DNETLIBS)
])

dnl find /proc/net/route or just give up and cry
AC_DEFUN(AC_UNI_PROCNETROUTE, [
AC_MSG_CHECKING(for a readable /proc/net/route file)
if test -r /proc/net/route; then
	AC_DEFINE(HAVE_PROC_NET_ROUTE)
	AC_MSG_RESULT(Yes)
else
	AC_MSG_RESULT(No)
fi
],
[])

dnl find pcap, or just make it
AC_DEFUN(AC_UNI_LIBPCAP, [
AC_MSG_CHECKING(for libpcap (http://www.tcpdump.org))
AC_CHECK_LIB(pcap, pcap_open_live,[
 AC_MSG_CHECKING(for pcap_lib_version)
 AC_CHECK_LIB(pcap, pcap_lib_version, AC_DEFINE(HAVE_PCAP_LIB_VERSION), [])
 AC_MSG_CHECKING(for pcap_setnonblock)
 AC_CHECK_LIB(pcap, pcap_setnonblock, AC_DEFINE(HAVE_PCAP_SET_NONBLOCK), [])
 AC_CHECK_LIB(pcap, pcap_get_selectable_fd, [],
[
  AC_DEFINE(HAVE_PCAP_LIB_VERSION)
  AC_DEFINE(HAVE_PCAP_SET_NONBLOCK)
  NEED_AUX_LIBS="${NEED_AUX_LIBS} pcap"
]
 )
],
[NEED_AUX_LIBS="${NEED_AUX_LIBS} pcap"
AC_DEFINE(HAVE_PCAP_LIB_VERSION)
AC_DEFINE(HAVE_PCAP_SET_NONBLOCK)])
])

AC_DEFUN(AC_UNI_LIBLTDL, [
AC_MSG_CHECKING(for libltdl)
AC_CHECK_LIB(ltdl, lt_dlopen, [], [
NEED_AUX_LIBS="${NEED_AUX_LIBS} libltdl"
])
])
