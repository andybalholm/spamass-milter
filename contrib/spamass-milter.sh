#! /bin/sh
#
# /usr/local/etc/rc.d script for FreeBSD
# $Id: spamass-milter.sh,v 1.3 2003/10/24 17:36:03 dnelson Exp $

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
