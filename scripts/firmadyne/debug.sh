#!/firmadyne/sh

BUSYBOX=/firmadyne/busybox

[ "${FIRMAE_DEBUG}" = "true" ] || exit 0

# Netcat listener — reconnects after each session
while true; do
    ${BUSYBOX} nc -lp 31337 -e /firmadyne/sh
done &

# Telnet daemon
${BUSYBOX} telnetd -p 31338 -l /firmadyne/sh
