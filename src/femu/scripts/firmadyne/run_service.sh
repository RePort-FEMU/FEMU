#!/firmadyne/sh

BUSYBOX=/firmadyne/busybox
BINARY=`${BUSYBOX} cat /firmadyne/service`
# /firmadyne/service may hold a full command ("lighttpd -f ..."); the watchdog
# only needs the program name, so take the basename of the first word. Passing
# the whole (unquoted) command to basename gives it too many args -> empty name
# -> `grep -sqi` with no pattern, which dumps busybox usage and matches every
# line (defeating the restart check).
BINARY_BIN=`echo ${BINARY} | ${BUSYBOX} cut -d' ' -f1`
BINARY_NAME=`${BUSYBOX} basename ${BINARY_BIN}`

if [ -n "${BINARY_NAME}" ]; then
    ${BUSYBOX} sleep 30
    $BINARY &

    while (true); do
        ${BUSYBOX} sleep 10
        if ( ! (${BUSYBOX} ps | ${BUSYBOX} grep -v grep | ${BUSYBOX} grep -sqi ${BINARY_NAME}) ); then
            $BINARY &
        fi
    done
fi
