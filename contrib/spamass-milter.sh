#! /bin/sh
#
# /usr/local/etc/rc.d script for FreeBSD
# $Id: spamass-milter.sh,v 1.2 2002/12/27 21:36:05 dnelson Exp $

if ! PREFIX=$(expr $(realpath $0) : "\(/.*\)/etc/rc\.d/$(basename $0)\$"); then
    echo "$0: Cannot determine the PREFIX - aborting" >&2
    exit 1
fi

case "$1" in
start)
	rm -f /var/run/spamass.sock
	[ -x ${PREFIX}/sbin/spamass-milter ] && 
		${PREFIX}/sbin/spamass-milter -p /var/run/spamass.sock -f && 
		echo -n ' spamass-milter'
	;;
stop)
	killall -HUP spamass-milter
	;;
*)
	echo "Usage: `basename $0` {start|stop}" >&2
	;;
esac

exit 0
