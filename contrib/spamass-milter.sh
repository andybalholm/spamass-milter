#! /bin/sh
#
# /usr/local/etc/rc.d script for FreeBSD
# $Id: spamass-milter.sh,v 1.4 2004/02/09 23:03:29 dnelson Exp $

# PROVIDE: spamass_milter
# KEYWORD: FreeBSD

. /usr/local/etc/rc.subr

name=spamass_milter
rcvar=`set_rcvar`

command=/usr/local/sbin/spamass-milter

# Override the spamass_milter_* variables in one of these files:
#	/etc/rc.conf
#	/etc/rc.conf.local
#	/etc/rc.conf.d/spamass-milter
#
# DO NOT CHANGE THESE DEFAULT VALUES HERE
#
# spamass_milter_enable     YES or NO
# spamass_milter_flags      extra flags to pass to spamass-milter
#
# You probably won't need to change these unless you're running as
# non-root (see the rc.subr manpage for those flags):
#
# spamass_milter_pidfile    path to pidfile
# spamass_milter_sockfile   path to milter socket

# load settings
load_rc_config $name

spamass_milter_enable=${spamass_milter_enable:-NO}
spamass_milter_pidfile=${spamass_milter_pidfile:-/var/run/spamass-milter.pid}
spamass_milter_sockfile=${spamass_milter_sockfile:-/var/run/spamass.sock}
pidfile=${spamass_milter_pidfile}
spamass_milter_flags="-p $spamass_milter_sockfile -f -P $spamass_milter_pidfile $spamass_milter_flags"

run_rc_command "$1"

exit 1


if ! PREFIX=$(expr $(realpath $0) : "\(/.*\)/etc/rc\.d/$(basename $0)\$"); then
    echo "$0: Cannot determine the PREFIX - aborting" >&2
    exit 1
fi

case "$1" in
start)
	rm -f /var/run/spamass.sock
	[ -x ${PREFIX}/sbin/spamass-milter ] && 
		${PREFIX}/sbin/spamass-milter -p /var/run/spamass.sock -f -P /var/run/spamass-milter.pid && 
		echo -n ' spamass-milter'
	;;
stop)
	if [ -s /var/run/spamass-milter.pid ] ; then
		pid=$(cat /var/run/spamass-milter.pid)
		kill -TERM $pid
		loop=0
		while [ $loop -lt 10 ] ; do
			kill -0 $pid >/dev/null 2>&1 || break
			[ $loop -eq 1 ] && echo -n "Sleeping for 10 seconds to allow spamass-milter to shutdown"
			[ $loop -ge 1 ] && echo -n "."
			sleep 1
			loop=$(( $loop + 1 ))
		done
		kill -0 $pid >/dev/null 2>&1 && echo "giving up" || echo "done"
	fi

	;;
*)
	echo "Usage: `basename $0` {start|stop}" >&2
	;;
esac

exit 0
