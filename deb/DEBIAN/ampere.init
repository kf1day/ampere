#!/bin/sh
set -e

### BEGIN INIT INFO
# Provides:             ampere
# Required-Start:       $local_fs $remote_fs $network $time
# Required-Stop:        $local_fs $remote_fs $network $time
# Should-Start:         $syslog
# Should-Stop:          $syslog
# Default-Start:        2 3 4 5
# Default-Stop:         0 1 6
# Short-Description:    An active network filter for Asterisk PBX
### END INIT INFO

# Setting environment variables for the postmaster here does not work; please
# set them in /etc/postgresql/<version>/<cluster>/environment instead.
SRV="ampere.service"

systemctl is-enabled $SRV > /dev/null || exit 0



case "$1" in
    start|stop|restart|reload|status)
        systemctl $1 $SRV
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|reload|status}"
        exit 1
        ;;
esac

exit 0
