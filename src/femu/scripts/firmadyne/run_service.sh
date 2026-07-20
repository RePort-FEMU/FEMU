#!/firmadyne/sh

BUSYBOX=/firmadyne/busybox
SERVICE_FILE=/firmadyne/service

# /firmadyne/service only exists when preparation found a service to keep alive.
# If it is missing there is nothing to watch, so exit quietly. This lets callers
# inject run_service.sh unconditionally instead of tracking whether a service
# was found.
if [ ! -f "${SERVICE_FILE}" ]; then
    exit 0
fi

BINARY=`${BUSYBOX} cat ${SERVICE_FILE}`
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
